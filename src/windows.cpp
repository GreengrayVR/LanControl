#include "windows.hpp"
#include <shellapi.h>
#include <shlobj.h>
#include <sddl.h>
#include <aclapi.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <stdexcept>
#include <atomic>

// Implemented in client.cpp; the SCM thread owns the service's Qt event loop.
int runClientService();
namespace lc::win {
namespace {
SERVICE_STATUS_HANDLE statusHandle = nullptr;
SERVICE_STATUS status{};
std::atomic<QCoreApplication*> serviceApp{nullptr};
struct Sc {
    SC_HANDLE h = nullptr;
    explicit Sc(SC_HANDLE value) : h(value) {}
    ~Sc() { if (h) CloseServiceHandle(h); }
    operator SC_HANDLE() const { return h; }
};
void require(bool ok, const char *what) {
    if (!ok) throw std::runtime_error((QString::fromLatin1(what) + " (Windows " + QString::number(GetLastError()) + ")").toStdString());
}
std::wstring native(const QString &s) { return QDir::toNativeSeparators(s).toStdWString(); }
void createProtectedDirectory(const QString &path) {
    // LocalSystem/admins can write; ordinary users can only read and execute.
    PSECURITY_DESCRIPTOR sd = nullptr;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)", SDDL_REVISION_1, &sd, nullptr), "Build ACL");
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), sd, FALSE};
    const auto p = native(path);
    const bool created = CreateDirectoryW(p.c_str(), &security) != FALSE;
    const DWORD result = GetLastError();
    LocalFree(sd); SetLastError(result); require(created, "Create protected directory (must not already exist)");
}
void copyData(const QString &from, const QString &to) {
    // Copy content into newly created protected files; never import source ACLs/permissions.
    QFile input(from); QSaveFile output(to);
    require(input.open(QIODevice::ReadOnly) && output.open(QIODevice::WriteOnly), "Open runtime copy");
    while (!input.atEnd()) {
        const auto bytes = input.read(1024 * 1024);
        require(!bytes.isEmpty() && output.write(bytes) == bytes.size(), "Copy runtime content");
    }
    require(input.error() == QFileDevice::NoError && output.commit(), "Commit runtime copy");
}
void copyTree(const QString &from, const QString &to) {
    const auto p = native(from); const DWORD attributes = GetFileAttributesW(p.c_str());
    require(attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_REPARSE_POINT), "Reject missing/reparse source");
    require(QDir().mkpath(to), "Create runtime directory");
    for (const auto &info : QDir(from).entryInfoList(QDir::NoDotAndDotDot | QDir::AllEntries | QDir::Hidden)) {
        const auto item = native(info.absoluteFilePath());
        require(!(GetFileAttributesW(item.c_str()) & FILE_ATTRIBUTE_REPARSE_POINT), "Reject reparse runtime entry");
        const auto dest = to + "/" + info.fileName();
        if (info.isDir()) copyTree(info.absoluteFilePath(), dest);
        else copyData(info.absoluteFilePath(), dest);
    }
}
bool waitState(SC_HANDLE s, DWORD wanted, int timeout = 30000) {
    QElapsedTimer elapsed; elapsed.start(); SERVICE_STATUS_PROCESS info{}; DWORD bytes = 0;
    while (elapsed.elapsed() < timeout) {
        if (!QueryServiceStatusEx(s, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&info), sizeof(info), &bytes)) return false;
        if (info.dwCurrentState == wanted) return true;
        Sleep(200);
    }
    return false;
}
bool stop(SC_HANDLE s) {
    SERVICE_STATUS state{};
    if (!ControlService(s, SERVICE_CONTROL_STOP, &state) && GetLastError() != ERROR_SERVICE_NOT_ACTIVE) return false;
    return waitState(s, SERVICE_STOPPED);
}
bool start(SC_HANDLE s) {
    if (!StartServiceW(s, 0, nullptr) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) return false;
    return waitState(s, SERVICE_RUNNING);
}
QString imagePath(int version) {
    return installDir() + "/versions/" + QString::number(version) + "/LanClient.exe";
}
void setImage(SC_HANDLE s, int version) {
    const auto command = (quote(imagePath(version)) + " --service").toStdWString();
    require(ChangeServiceConfigW(s, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
        command.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr), "Set service image");
}
void report(DWORD state, DWORD error = NO_ERROR, DWORD hint = 0) {
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state; status.dwWin32ExitCode = error;
    status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    status.dwCheckPoint = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING ? 1 : 0;
    status.dwWaitHint = hint;
    if (statusHandle) SetServiceStatus(statusHandle, &status);
}
DWORD WINAPI control(DWORD code, DWORD, LPVOID, LPVOID) {
    if (code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN) {
        report(SERVICE_STOP_PENDING, NO_ERROR, 10000);
        if (auto app = serviceApp.load()) QMetaObject::invokeMethod(app, [] { QCoreApplication::quit(); }, Qt::QueuedConnection);
        return NO_ERROR;
    }
    if (code == SERVICE_CONTROL_INTERROGATE) { SetServiceStatus(statusHandle, &status); return NO_ERROR; }
    return ERROR_CALL_NOT_IMPLEMENTED;
}
void WINAPI serviceMain(DWORD, LPWSTR*) {
    statusHandle = RegisterServiceCtrlHandlerExW(L"LanControlClient", control, nullptr);
    if (!statusHandle) return;
    report(SERVICE_START_PENDING, NO_ERROR, 15000);
    int result = 1;
    try { result = runClientService(); }
    catch (const std::exception &e) { log(QString::fromUtf8(e.what())); }
    serviceApp.store(nullptr);
    report(SERVICE_STOPPED, result == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR);
}
}
QString quote(const QString &s) { return '"' + QDir::toNativeSeparators(s) + '"'; }
bool elevated() { return IsUserAnAdmin() != FALSE; }
bool elevate(const QString &arguments) {
    const auto exe = executable().toStdWString(); const auto args = arguments.toStdWString();
    return reinterpret_cast<INT_PTR>(ShellExecuteW(nullptr, L"runas", exe.c_str(), args.c_str(), nullptr, SW_SHOWNORMAL)) > 32;
}
QString activeExecutable() {
    const auto m = readJson(dataDir() + "/current.json");
    const int v = m.value("version").toInt();
    return v > 0 ? imagePath(v) : QString{};
}
void install() {
    require(elevated(), "Administrator rights required");
#ifdef LANCONTROL_SINGLE_FILE_CLIENT
    const auto cfg = readJson(":/lancontrol/client.json");
#else
    const auto cfg = readJson(QCoreApplication::applicationDirPath() + "/client.json");
#endif
    require(validClientConfig(cfg),
            "Invalid client.json (expected server 6kabinet and valid token/pin)");
    Sc manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE)); require(manager.h, "Open SCM");
    Sc existing(OpenServiceW(manager, L"LanControlClient", SERVICE_QUERY_STATUS));
    require(!existing.h && GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST, "Client is already installed");
    // Refuse attacker-precreated directories; never grant SYSTEM execution to untrusted files.
    require(!QFileInfo::exists(installDir()) && !QFileInfo::exists(dataDir()), "Remove old LanControl directories before fresh installation");
    createProtectedDirectory(installDir()); createProtectedDirectory(dataDir());
    require(QDir().mkpath(dataDir() + "/staging"), "Create staging directory");
    require(QDir().mkpath(dataDir() + "/commands"), "Create browser queue");
#ifdef LANCONTROL_SINGLE_FILE_CLIENT
    // A standalone EXE may be launched from a Desktop or USB root. Never copy its neighbours.
    copyData(executable(), installDir() + "/LanClient.exe");
    require(QDir().mkpath(QFileInfo(imagePath(LANCONTROL_VERSION_CODE)).absolutePath()), "Create version directory");
    copyData(executable(), imagePath(LANCONTROL_VERSION_CODE));
#else
    copyTree(QCoreApplication::applicationDirPath(), installDir());
    copyTree(QCoreApplication::applicationDirPath(), QFileInfo(imagePath(LANCONTROL_VERSION_CODE)).absolutePath());
#endif
    require(writeJson(dataDir() + "/client.json", cfg), "Write enrollment");
    require(writeJson(dataDir() + "/current.json", {{"version", LANCONTROL_VERSION_CODE}}), "Write active version");
    QSettings run("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", QSettings::NativeFormat);
    run.setValue("LanControlAgent", quote(installDir() + "/LanClient.exe") + " --agent"); run.sync();
    require(run.status() == QSettings::NoError, "Register all-user startup");
    const auto command = (quote(imagePath(LANCONTROL_VERSION_CODE)) + " --service").toStdWString();
    Sc service(CreateServiceW(manager, L"LanControlClient", L"LanControl Client", SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, command.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr));
    require(service.h, "Register Windows service");
    SERVICE_DESCRIPTIONW desc{const_cast<wchar_t*>(L"Opens administrator-provided LAN links in user browsers; checks for authenticated updates.")};
    ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &desc);
    SC_ACTION actions[]{{SC_ACTION_RESTART, 20000}, {SC_ACTION_RESTART, 20000}, {SC_ACTION_RESTART, 20000}};
    SERVICE_FAILURE_ACTIONSW failure{86400, nullptr, nullptr, 3, actions};
    require(ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, &failure), "Set service recovery");
    require(start(service), "Start installed service");
    log("Installation completed");
}
void uninstall() {
    require(elevated(), "Administrator rights required");
    Sc manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)); require(manager.h, "Open SCM");
    Sc service(OpenServiceW(manager, L"LanControlClient", SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE));
    if (service.h) { require(stop(service), "Stop service"); require(DeleteService(service), "Delete service"); }
    else require(GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST, "Open service");
    QSettings run("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", QSettings::NativeFormat);
    run.remove("LanControlAgent"); run.sync();
    QFile::remove(dataDir() + "/current.json"); // agents observe this and leave within one second
    log("Uninstalled. Installation/data directories can now be removed by an administrator.");
}
void applyUpdate(int version) {
    require(elevated(), "Only SYSTEM/admin can update");
    QLockFile lock(dataDir() + "/update.lock"); require(lock.tryLock(), "Update already running");
    const int old = readJson(dataDir() + "/current.json").value("version").toInt();
    const auto manifest = readJson(dataDir() + "/staging/manifest.json");
    const auto download = dataDir() + "/staging/LanClient.download";
    require(version == manifest.value("version").toInt() && validManifest(manifest, old) &&
            verifyDownload(download, manifest), "Reject invalid/old update");
    const auto dest = QFileInfo(imagePath(version)).absolutePath();
    require(!QFileInfo::exists(dest), "Version directory already exists; inspect previous failed update");
    copyTree(QFileInfo(imagePath(old)).absolutePath(), dest);
    copyData(download, imagePath(version));
    Sc manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)); require(manager.h, "Open SCM");
    Sc service(OpenServiceW(manager, L"LanControlClient", SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG));
    require(service.h, "Open service"); require(stop(service), "Stop for update");
    bool committed = false;
    try {
        setImage(service, version);
        require(writeJson(dataDir() + "/current.json", {{"version", version}}), "Switch version");
        require(start(service), "New service failed to start");
        // Stability window: a process that immediately crashes must not commit an update.
        Sleep(5000); require(waitState(service, SERVICE_RUNNING, 1000), "New service exited during startup");
        committed = true;
    } catch (...) {
        stop(service); setImage(service, old);
        writeJson(dataDir() + "/current.json", {{"version", old}});
        const bool recovered = start(service);
        writeJson(dataDir() + "/failed-update.json", {{"version", version}, {"recovered", recovered}});
        log(recovered ? "Update failed; previous version restored" : "Update and rollback startup failed; administrator action required");
        throw;
    }
    if (committed) {
        QFile::remove(download); QFile::remove(dataDir() + "/staging/manifest.json");
        QFile::remove(dataDir() + "/failed-update.json");
        log("Updated successfully to " + QString::number(version));
    }
}
int dispatchService() {
    SERVICE_TABLE_ENTRYW entries[]{{const_cast<wchar_t*>(L"LanControlClient"), serviceMain}, {nullptr, nullptr}};
    return StartServiceCtrlDispatcherW(entries) ? 0 : int(GetLastError());
}
void reportRunning() { serviceApp.store(QCoreApplication::instance()); report(SERVICE_RUNNING); }
void launchAgents() {
    PWTS_SESSION_INFOW sessions = nullptr; DWORD count = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) return;
    for (DWORD i = 0; i < count; ++i) {
        if (sessions[i].State != WTSActive || sessions[i].SessionId == 0) continue;
        const auto mutexName = ("Global\\LanControlAgent-" + QString::number(sessions[i].SessionId)).toStdWString();
        HANDLE mutex = OpenMutexW(SYNCHRONIZE, FALSE, mutexName.c_str());
        if (mutex) { CloseHandle(mutex); continue; }
        if (GetLastError() == ERROR_ACCESS_DENIED) continue;
        HANDLE token = nullptr;
        if (!WTSQueryUserToken(sessions[i].SessionId, &token)) continue;
        void *environment = nullptr; CreateEnvironmentBlock(&environment, token, FALSE);
        STARTUPINFOW info{}; info.cb = sizeof(info); info.lpDesktop = const_cast<wchar_t*>(L"winsta0\\default");
        PROCESS_INFORMATION process{};
        const auto exe = native(activeExecutable()); auto command = (quote(activeExecutable()) + " --agent").toStdWString();
        if (CreateProcessAsUserW(token, exe.c_str(), command.data(), nullptr, nullptr, FALSE,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, environment, nullptr, &info, &process)) {
            CloseHandle(process.hProcess); CloseHandle(process.hThread);
        }
        if (environment) DestroyEnvironmentBlock(environment); CloseHandle(token);
    }
    WTSFreeMemory(sessions);
}
}
