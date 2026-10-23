#include "common.hpp"

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    const auto args = app.arguments();
    if (args.size() < 3 || args.size() > 5) return 2;
    const QString host = args[1], name = args[2];
    auto config = lc::readJson(":/lancontrol/client.json");
    if (!lc::validClientConfig(config)) return 3;
    if (args.size() >= 4) config["certificateSha256"] = args[3];
    const QString peerName = args.size() >= 5 ? args[4] : QString("6kabinet");
    if (!QSslSocket::setActiveBackend("schannel") || !QSslSocket::supportsSsl()) return 4;
    QSslSocket socket;
    lc::Frames frames;
    int result = -1;
    const auto finish = [&](int code) {
        if (result < 0) { result = code; app.exit(code); }
    };
    socket.setProtocol(QSsl::TlsV1_2OrLater);
    socket.setPeerVerifyMode(QSslSocket::VerifyPeer);
    socket.setPeerVerifyName(peerName);
    QObject::connect(&socket, &QSslSocket::sslErrors, &app, [&](const QList<QSslError> &errors) {
        if (lc::allowPinnedCertificateErrors(socket, config.value("certificateSha256").toString(), errors))
            socket.ignoreSslErrors(errors);
        else finish(5);
    });
    QObject::connect(&socket, &QSslSocket::encrypted, &app, [&] {
        if (!lc::pinnedCertificate(socket, config.value("certificateSha256").toString())) { finish(6); return; }
        lc::send(&socket, {{"type", "hello"}, {"name", name}, {"token", config.value("token")}, {"version", LANCONTROL_VERSION_CODE}});
    });
    QObject::connect(&socket, &QSslSocket::readyRead, &app, [&] {
        if (!frames.feed(socket.readAll(), [&](QJsonObject message) {
            if (message.value("type") == "welcome") lc::send(&socket, {{"type", "ping"}});
            else if (message.value("type") == "pong") finish(0);
            else finish(7);
        })) finish(8);
    });
    QObject::connect(&socket, &QSslSocket::errorOccurred, &app, [&](auto) {
        QTextStream(stderr) << socket.errorString() << Qt::endl;
        finish(9);
    });
    QObject::connect(&socket, &QSslSocket::disconnected, &app, [&] { finish(12); });
    QTimer::singleShot(15000, &app, [&] { finish(13); });
    socket.connectToHostEncrypted(host, lc::Port);
    return app.exec();
}
