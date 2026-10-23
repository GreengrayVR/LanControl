#pragma once
#include <QtCore>
#include <QtNetwork>
#include <functional>
#include <climits>
#include <stdexcept>

namespace lc {
inline constexpr quint16 Port = 47666;
inline constexpr int HeartbeatMs = 20000;
inline constexpr int OfflineMs = 65000;
inline constexpr qint64 MaxUpdate = 128 * 1024 * 1024;
inline constexpr qsizetype MaxFrame = 256 * 1024;
inline constexpr char ServiceName[] = "LanControlClient";
QString dataDir();
QString installDir();
QString executable();
QJsonObject readJson(const QString &path);
bool writeJson(const QString &path, const QJsonObject &object);
bool validUrl(const QString &text);
bool validName(const QString &name);
bool validClientConfig(const QJsonObject &config);
bool pinnedCertificate(const QSslSocket &socket, const QString &pin);
bool allowPinnedCertificateErrors(const QSslSocket &socket, const QString &pin, const QList<QSslError> &errors);
QString normalizedName(const QString &name);
QByteArray sha256File(const QString &path);
QString newId();
void log(const QString &message);
bool validManifest(const QJsonObject &m, int currentVersion);
bool verifyDownload(const QString &file, const QJsonObject &m);
void send(QSslSocket *socket, const QJsonObject &object);
// Bounded newline-delimited JSON parser. A bad/oversized frame closes its connection.
class Frames {
    QByteArray pending;
public:
    bool feed(const QByteArray &data, const std::function<void(QJsonObject)> &receive);
};
}
