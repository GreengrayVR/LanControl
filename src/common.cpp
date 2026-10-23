#include "common.hpp"
#include <windows.h>
#include <shlobj.h>

namespace lc {
QString knownFolder(REFKNOWNFOLDERID id) {
    PWSTR value = nullptr;
    if (FAILED(SHGetKnownFolderPath(id, 0, nullptr, &value))) return {};
    QString result = QString::fromWCharArray(value);
    CoTaskMemFree(value);
    return QDir::fromNativeSeparators(result);
}
QString dataDir() { return knownFolder(FOLDERID_ProgramData) + "/LanControl"; }
QString installDir() { return knownFolder(FOLDERID_ProgramFiles) + "/LanControl"; }
QString executable() { return QDir::toNativeSeparators(QCoreApplication::applicationFilePath()); }
QJsonObject readJson(const QString &path) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly) || f.size() > MaxFrame) return {};
    QJsonParseError e;
    auto doc = QJsonDocument::fromJson(f.readAll(), &e);
    return e.error == QJsonParseError::NoError && doc.isObject() ? doc.object() : QJsonObject{};
}
bool writeJson(const QString &path, const QJsonObject &object) {
    QSaveFile f(path);
    if (!f.open(QIODevice::WriteOnly)) return false;
    auto bytes = QJsonDocument(object).toJson(QJsonDocument::Compact);
    return f.write(bytes) == bytes.size() && f.commit();
}
bool validUrl(const QString &text) {
    if (text.size() > 8192 || text.isEmpty() || text != text.trimmed()) return false;
    for (const auto c : text) if (c.unicode() < 32 || c.unicode() == 127 || c == '\\') return false;
    const QUrl u(text, QUrl::StrictMode);
    return u.isValid() && (u.scheme() == "http" || u.scheme() == "https") &&
           !u.host().isEmpty() && u.userInfo().isEmpty();
}
QString normalizedName(const QString &name) { return name.trimmed().toUpper(); }
bool validClientConfig(const QJsonObject &config) {
    static const QRegularExpression hex("^[a-f0-9]{64}$");
    return config.value("server") == "6kabinet" && config.value("port").toInt() == Port &&
        hex.match(config.value("token").toString()).hasMatch() &&
        hex.match(config.value("certificateSha256").toString()).hasMatch();
}
bool pinnedCertificate(const QSslSocket &socket, const QString &pin) {
    return !socket.peerCertificate().isNull() &&
        socket.peerCertificate().digest(QCryptographicHash::Sha256).toHex() == pin.toLatin1();
}
bool allowPinnedCertificateErrors(const QSslSocket &socket, const QString &pin, const QList<QSslError> &errors) {
    if (!pinnedCertificate(socket, pin)) return false;
    for (const auto &e : errors) {
        if (e.error() != QSslError::SelfSignedCertificate && e.error() != QSslError::CertificateUntrusted &&
            e.error() != QSslError::UnableToGetLocalIssuerCertificate && e.error() != QSslError::UnableToVerifyFirstCertificate)
            return false;
    }
    return true;
}
bool validName(const QString &name) {
    static const QRegularExpression r("^[A-Z0-9][A-Z0-9-]{0,62}$");
    return r.match(name).hasMatch();
}
QByteArray sha256File(const QString &path) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return {};
    QCryptographicHash h(QCryptographicHash::Sha256);
    if (!h.addData(&f)) return {};
    return h.result().toHex();
}
QString newId() { return QUuid::createUuid().toString(QUuid::WithoutBraces); }
void log(const QString &message) {
    QFile f(dataDir() + "/client.log");
    if (f.size() > 2 * 1024 * 1024) {
        QFile::remove(f.fileName() + ".old");
        QFile::rename(f.fileName(), f.fileName() + ".old");
    }
    if (f.open(QIODevice::WriteOnly | QIODevice::Append))
        f.write((QDateTime::currentDateTimeUtc().toString(Qt::ISODate) + " " + message + "\n").toUtf8());
}
bool validManifest(const QJsonObject &m, int currentVersion) {
    const double v = m.value("version").toDouble(-1);
    const double n = m.value("size").toDouble(-1);
    static const QRegularExpression hash("^[0-9a-f]{64}$");
    return v > currentVersion && v <= INT_MAX && v == qint64(v) &&
           n > 0 && n <= MaxUpdate && n == qint64(n) &&
           hash.match(m.value("sha256").toString()).hasMatch();
}
bool verifyDownload(const QString &file, const QJsonObject &m) {
    return QFileInfo(file).size() == m.value("size").toInteger(-1) &&
           sha256File(file) == m.value("sha256").toString().toLatin1();
}
void send(QSslSocket *socket, const QJsonObject &object) {
    socket->write(QJsonDocument(object).toJson(QJsonDocument::Compact) + '\n');
}
bool Frames::feed(const QByteArray &data, const std::function<void(QJsonObject)> &receive) {
    pending += data;
    while (true) {
        const auto end = pending.indexOf('\n');
        if (end < 0) return pending.size() <= MaxFrame;
        if (end == 0 || end > MaxFrame) return false;
        QJsonParseError e;
        auto doc = QJsonDocument::fromJson(pending.first(end), &e);
        pending.remove(0, end + 1);
        if (e.error != QJsonParseError::NoError || !doc.isObject()) return false;
        receive(doc.object());
    }
}
}
