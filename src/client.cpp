#include "windows.hpp"
#include <shellapi.h>
#include <memory>
#include <stdexcept>

class Client : public QObject {
    QSslSocket socket;
    lc::Frames frames;
    QTimer heartbeat, updateTimer, agentTimer, watchdog;
    QJsonObject config, manifest;
    std::unique_ptr<QSaveFile> download;
    qint64 received = 0, lastReply = 0, connectingSince = 0;
    bool authenticated = false, manifestRequested = false, applying = false;

    bool pinned() const {
        return lc::pinnedCertificate(socket, config.value("certificateSha256").toString());
    }
    void askManifest() {
        if (authenticated && !manifestRequested && !download && !applying) {
            manifestRequested = true; lc::send(&socket, {{"type", "manifest"}});
        }
    }
    void reconnect() {
        if (socket.state() == QAbstractSocket::UnconnectedState) {
            frames = {}; authenticated = false; manifestRequested = false;
            connectingSince = QDateTime::currentMSecsSinceEpoch();
            socket.connectToHostEncrypted(config.value("server").toString(), lc::Port);
        } else if (authenticated) {
            lc::send(&socket, {{"type", "ping"}});
        }
    }
    void fail(const QString &why) { lc::log(why); socket.abort(); }
    void onMessage(const QJsonObject &m) {
        const auto type = m.value("type").toString();
        lastReply = QDateTime::currentMSecsSinceEpoch();
        if (!authenticated) {
            if (type != "welcome") { fail("Invalid authentication response"); return; }
            authenticated = true; lc::log("Authenticated to 6kabinet"); askManifest(); return;
        }
        if (type == "pong") return;
        if (type == "open") {
            const auto id = m.value("id").toString();
            const auto expires = m.value("expires").toInteger(); const auto now = QDateTime::currentSecsSinceEpoch();
            if (QUuid(id).isNull() || !lc::validUrl(m.value("url").toString()) || expires < now || expires > now + 120) {
                lc::send(&socket, {{"type", "ack"}, {"id", id.left(36)}, {"status", "rejected"}}); return;
            }
            const auto file = lc::dataDir() + "/commands/" + QUuid(id).toString(QUuid::WithoutBraces) + ".json";
            const bool saved = QFileInfo::exists(file) ||
                (QDir(lc::dataDir() + "/commands").entryList({"*.json"}, QDir::Files).size() < 256 && lc::writeJson(file, m));
            lc::send(&socket, {{"type", "ack"}, {"id", id}, {"status", saved ? "accepted by service" : "mailbox write failed"}});
            lc::log(saved ? "Browser command accepted" : "Browser command could not be saved"); return;
        }
        if (type == "no_update") { manifestRequested = false; return; }
        if (type == "manifest") {
            if (!manifestRequested || download) { fail("Unexpected update manifest"); return; }
            manifestRequested = false;
            if (!lc::validManifest(m, LANCONTROL_VERSION_CODE)) { fail("Invalid update manifest"); return; }
            if (lc::readJson(lc::dataDir() + "/failed-update.json").value("version") == m.value("version")) {
                lc::log("Skipping previously failed release; publish a higher release number"); return;
            }
            manifest = m; received = 0;
            download = std::make_unique<QSaveFile>(lc::dataDir() + "/staging/LanClient.download");
            if (!download->open(QIODevice::WriteOnly)) { download.reset(); fail("Cannot open update staging"); return; }
            lc::send(&socket, {{"type", "chunk"}, {"offset", 0}}); return;
        }
        if (type == "chunk") {
            if (!download || m.value("offset").toInteger(-1) != received) { fail("Unexpected update offset"); return; }
            const auto encoded = m.value("data").toString().toLatin1();
            const auto decoded = QByteArray::fromBase64Encoding(encoded, QByteArray::AbortOnBase64DecodingErrors);
            const auto &bytes = decoded.decoded;
            const auto size = manifest.value("size").toInteger();
            if (!decoded || bytes.isEmpty() || bytes.size() > 48 * 1024 || received + bytes.size() > size ||
                download->write(bytes) != bytes.size()) { fail("Invalid update chunk"); return; }
            received += bytes.size();
            if (received < size) { lc::send(&socket, {{"type", "chunk"}, {"offset", received}}); return; }
            if (!download->commit()) { download.reset(); fail("Cannot commit update download"); return; }
            download.reset();
            if (!lc::verifyDownload(lc::dataDir() + "/staging/LanClient.download", manifest) ||
                !lc::writeJson(lc::dataDir() + "/staging/manifest.json", manifest)) {
                QFile::remove(lc::dataDir() + "/staging/LanClient.download"); fail("Update SHA-256/metadata validation failed"); return;
            }
            applying = QProcess::startDetached(lc::installDir() + "/LanClient.exe",
                {"--apply-update", QString::number(manifest.value("version").toInt())});
            if (applying) QTimer::singleShot(120000, this, [this] { applying = false; });
            lc::log(applying ? "Validated update; starting updater" : "Could not start updater"); return;
        }
        fail("Unknown server message");
    }
public:
    ~Client() override { QObject::disconnect(&socket, nullptr, this, nullptr); socket.abort(); }
    Client() {
        config = lc::readJson(lc::dataDir() + "/client.json");
        if (!lc::validClientConfig(config))
            throw std::runtime_error("Missing/invalid installed client configuration");
        if (lc::readJson(lc::dataDir() + "/current.json").value("version").toInt() != LANCONTROL_VERSION_CODE)
            throw std::runtime_error("Published executable version does not match update manifest");
        socket.setReadBufferSize(lc::MaxFrame * 2); socket.setProtocol(QSsl::TlsV1_2OrLater);
        socket.setPeerVerifyMode(QSslSocket::VerifyPeer); socket.setPeerVerifyName("6kabinet");
        connect(&socket, &QSslSocket::sslErrors, this, [this](const QList<QSslError> &errors) {
            // Permit only the pinned self-signed certificate; never ignore hostname/expiry errors.
            const bool allowed = lc::allowPinnedCertificateErrors(socket, config.value("certificateSha256").toString(), errors);
            if (allowed) socket.ignoreSslErrors(errors); else fail("TLS certificate rejected");
        });
        connect(&socket, &QSslSocket::encrypted, this, [this] {
            if (!pinned()) { fail("TLS certificate pin mismatch"); return; }
            QString name = lc::normalizedName(QSysInfo::machineHostName().section('.', 0, 0));
            lc::send(&socket, {{"type", "hello"}, {"name", name}, {"token", config.value("token")},
                               {"version", LANCONTROL_VERSION_CODE}});
        });
        connect(&socket, &QSslSocket::readyRead, this, [this] {
            if (!frames.feed(socket.readAll(), [this](QJsonObject m) { onMessage(m); })) fail("Invalid protocol frame");
        });
        connect(&socket, &QSslSocket::disconnected, this, [this] {
            authenticated = false; manifestRequested = false;
            if (download) { download->cancelWriting(); download.reset(); }
            lc::log("Disconnected; next attempt within 20 seconds");
        });
        connect(&socket, &QSslSocket::errorOccurred, this, [](auto) { lc::log("Network connection error"); });
        heartbeat.setInterval(lc::HeartbeatMs); connect(&heartbeat, &QTimer::timeout, this, [this] { reconnect(); }); heartbeat.start();
        updateTimer.setInterval(10 * 60 * 1000); connect(&updateTimer, &QTimer::timeout, this, [this] { askManifest(); }); updateTimer.start();
        agentTimer.setInterval(lc::HeartbeatMs); connect(&agentTimer, &QTimer::timeout, this, [] {
            lc::win::launchAgents();
            for (const auto &entry : QDir(lc::dataDir() + "/commands").entryInfoList({"*.json"}, QDir::Files)) {
                if (lc::readJson(entry.absoluteFilePath()).value("expires").toInteger() < QDateTime::currentSecsSinceEpoch())
                    QFile::remove(entry.absoluteFilePath());
            }
        }); agentTimer.start();
        watchdog.setInterval(1000); connect(&watchdog, &QTimer::timeout, this, [this] {
            const auto now = QDateTime::currentMSecsSinceEpoch();
            if (socket.state() != QAbstractSocket::UnconnectedState &&
                ((!authenticated && now - connectingSince > 15000) || (authenticated && now - lastReply > lc::OfflineMs)))
                fail("Connection timeout");
        }); watchdog.start();
        reconnect(); lc::win::launchAgents();
    }
};

int runClientService() {
    int argc = 1; char program[] = "LanClient"; char *argv[]{program, nullptr};
    QCoreApplication app(argc, argv);
#ifdef LANCONTROL_SINGLE_FILE_CLIENT
    const QString backend = "schannel";
#else
    const QString backend = "openssl";
#endif
    if (!QSslSocket::setActiveBackend(backend) || !QSslSocket::supportsSsl())
        throw std::runtime_error("Configured Qt TLS backend is unavailable");
    Client client;
    lc::win::reportRunning(); return app.exec();
}

int runAgent(QCoreApplication &app) {
    auto active = lc::win::activeExecutable();
    if (active.isEmpty()) return 0;
    if (QFileInfo(active).canonicalFilePath().compare(QFileInfo(lc::executable()).canonicalFilePath(), Qt::CaseInsensitive) != 0)
        return QProcess::startDetached(active, {"--agent"}) ? 0 : 1;
    DWORD session = 0; ProcessIdToSessionId(GetCurrentProcessId(), &session);
    const auto name = ("Global\\LanControlAgent-" + QString::number(session)).toStdWString();
    HANDLE mutex = CreateMutexW(nullptr, FALSE, name.c_str());
    if (!mutex || GetLastError() == ERROR_ALREADY_EXISTS) { if (mutex) CloseHandle(mutex); return 0; }
    QSettings state("LanControl", "Agent");
    const auto setting = "lastCommand/" + QString::number(session);
    QStringList seen = state.value(setting).toStringList();
    QTimer timer; timer.setInterval(1000);
    QObject::connect(&timer, &QTimer::timeout, &app, [&] {
        const auto current = lc::win::activeExecutable();
        if (current.isEmpty()) { app.quit(); return; }
        if (QFileInfo(current).canonicalFilePath().compare(QFileInfo(lc::executable()).canonicalFilePath(), Qt::CaseInsensitive) != 0) {
            // Release singleton before spawning the updated agent.
            if (mutex) { CloseHandle(mutex); mutex = nullptr; }
            QProcess::startDetached(current, {"--agent"}); app.quit(); return;
        }
        for (const auto &entry : QDir(lc::dataDir() + "/commands").entryInfoList({"*.json"}, QDir::Files, QDir::Time | QDir::Reversed)) {
        const auto command = lc::readJson(entry.absoluteFilePath());
        const auto id = command.value("id").toString();
        if (id.isEmpty() || seen.contains(id)) continue;
        seen.append(id); while (seen.size() > 512) seen.removeFirst();
        state.setValue(setting, seen); state.sync();
        const auto expires = command.value("expires").toInteger(); const auto now = QDateTime::currentSecsSinceEpoch();
        const auto url = command.value("url").toString();
        if (expires < now || expires > now + 120 || !lc::validUrl(url)) continue;
        const auto nativeUrl = QUrl(url, QUrl::StrictMode).toString(QUrl::FullyEncoded).toStdWString();
        const auto result = reinterpret_cast<INT_PTR>(ShellExecuteW(nullptr, L"open", nativeUrl.c_str(), nullptr, nullptr, SW_SHOWNORMAL));
        state.setValue("lastBrowserLaunch", result > 32 ? "ok" : "failed");
        }
    }); timer.start();
    const int result = app.exec(); if (mutex) CloseHandle(mutex); return result;
}
int main(int argc, char **argv) {
    // Service dispatcher must run before constructing QCoreApplication on the SCM thread.
    bool service = false;
    for (int i = 1; i < argc; ++i) if (QByteArray(argv[i]) == "--service") service = true;
    if (service) return lc::win::dispatchService();
    QCoreApplication app(argc, argv); const auto args = app.arguments();
    const auto mode = args.size() > 1 ? args[1] : "--install";
#ifdef LANCONTROL_SINGLE_FILE_CLIENT
    if (mode == "--self-test") {
        if (!lc::validClientConfig(lc::readJson(":/lancontrol/client.json"))) return 10;
        return QSslSocket::setActiveBackend("schannel") && QSslSocket::supportsSsl() ? 0 : 11;
    }
#endif
    if (mode == "--agent") return runAgent(app);
    if (mode != "--install" && mode != "--uninstall" && mode != "--apply-update") return 2;
    if (!lc::win::elevated()) {
        if (mode == "--apply-update") return 5;
        return lc::win::elevate(mode) ? 0 : 5;
    }
    try {
        if (mode == "--install") {
            lc::win::install(); MessageBoxW(nullptr, L"Клієнт встановлено. Служба запущена; автозапуск налаштовано для всіх користувачів.", L"LanControl", MB_OK | MB_ICONINFORMATION);
        } else if (mode == "--uninstall") {
            lc::win::uninstall(); MessageBoxW(nullptr, L"Службу та автозапуск видалено. Каталоги LanControl можна видалити вручну після завершення агентів.", L"LanControl", MB_OK | MB_ICONINFORMATION);
        } else {
            bool ok = false; const int v = args.value(2).toInt(&ok);
            if (!ok || v <= 0) return 2;
            lc::win::applyUpdate(v);
        }
        return 0;
    } catch (const std::exception &e) {
        lc::log(QString::fromUtf8(e.what()));
        if (mode != "--apply-update") MessageBoxW(nullptr, QString::fromUtf8(e.what()).toStdWString().c_str(), L"LanControl", MB_OK | MB_ICONERROR);
        return 1;
    }
}
