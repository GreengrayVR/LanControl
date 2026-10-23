#include "common.hpp"
#include <QtWidgets>
#include <memory>

struct Computer {
    QString name, token;
    QSslSocket *socket = nullptr;
    qint64 seen = 0;
    int version = 0;
};
struct Peer {
    lc::Frames frames;
    QString name;
    QFile update;
    QJsonObject manifest;
    qint64 offset = 0;
    qint64 born = QDateTime::currentMSecsSinceEpoch();
};
class Listener : public QTcpServer {
public:
    std::function<void(qintptr)> accepted;
    using QTcpServer::QTcpServer;
protected:
    void incomingConnection(qintptr handle) override { accepted(handle); }
};
class Window : public QMainWindow {
    QString base;
    QString sharedClientToken;
    QMap<QString, Computer> computers;
    QHash<QSslSocket*, std::shared_ptr<Peer>> peers;
    Listener listener{this};
    QSslCertificate cert;
    QSslKey key;
    QTableWidget *table;
    QLineEdit *url;
    QPlainTextEdit *events;
    QSystemTrayIcon *tray;
    bool exiting = false;

    void note(const QString &s) { events->appendPlainText(QTime::currentTime().toString("HH:mm:ss ") + s); }
    void refresh() {
        for (int row = 0; row < table->rowCount(); ++row) {
            auto &c = computers[table->item(row, 0)->text()];
            const bool online = c.socket && c.socket->isEncrypted() &&
                QDateTime::currentMSecsSinceEpoch() - c.seen < lc::OfflineMs;
            table->item(row, 1)->setText(online ? QString::fromUtf8("Підключено") : QString::fromUtf8("Відключено"));
            table->item(row, 1)->setForeground(online ? QColor(0, 140, 45) : QColor(195, 35, 35));
            table->item(row, 2)->setText(c.version ? QString::number(c.version) : "—");
        }
    }
    void drop(QSslSocket *s) { s->abort(); }
    void message(QSslSocket *s, const std::shared_ptr<Peer> &p, const QJsonObject &m) {
        if (!s->isEncrypted()) return;
        const auto type = m.value("type").toString();
        if (p->name.isEmpty()) {
            const auto name = lc::normalizedName(m.value("name").toString());
            const auto token = m.value("token").toString();
            if (type != "hello" || !computers.contains(name) ||
                (token != computers[name].token && (sharedClientToken.isEmpty() || token != sharedClientToken))) {
                drop(s); return;
            }
            auto &c = computers[name];
            if (c.socket && c.socket != s) { drop(s); return; }
            p->name = name; c.socket = s; c.seen = QDateTime::currentMSecsSinceEpoch();
            c.version = m.value("version").toInt();
            lc::send(s, {{"type", "welcome"}});
            note(name + QString::fromUtf8(" підключено")); refresh(); return;
        }
        auto &c = computers[p->name];
        if (c.socket != s) { drop(s); return; }
        c.seen = QDateTime::currentMSecsSinceEpoch();
        if (type == "ping") { lc::send(s, {{"type", "pong"}}); }
        else if (type == "ack") {
            note(p->name + ": " + m.value("id").toString().left(36) + " " + m.value("status").toString().left(80));
        } else if (type == "manifest") {
            // Keep an open file per transfer, so publication of another release cannot mix chunks.
            p->update.close(); p->manifest = lc::readJson(base + "/updates/manifest.json");
            p->update.setFileName(base + "/updates/LanClient.exe");
            p->offset = 0;
            if (!lc::validManifest(p->manifest, c.version) ||
                !lc::verifyDownload(p->update.fileName(), p->manifest) || !p->update.open(QIODevice::ReadOnly)) {
                p->update.close(); lc::send(s, {{"type", "no_update"}}); return;
            }
            auto answer = p->manifest; answer["type"] = "manifest"; lc::send(s, answer);
        } else if (type == "chunk") {
            if (!p->update.isOpen() || m.value("offset").toInteger(-1) != p->offset) { drop(s); return; }
            const auto bytes = p->update.read(48 * 1024);
            if (bytes.isEmpty()) { p->update.close(); drop(s); return; }
            lc::send(s, {{"type", "chunk"}, {"offset", p->offset},
                         {"data", QString::fromLatin1(bytes.toBase64())}});
            p->offset += bytes.size();
            if (p->offset == p->manifest.value("size").toInteger()) p->update.close();
        } else { drop(s); }
    }
    void accept(qintptr descriptor) {
        auto s = new QSslSocket(this);
        if (!s->setSocketDescriptor(descriptor)) { s->deleteLater(); return; }
        if (peers.size() >= 512) { s->abort(); s->deleteLater(); return; }
        s->setReadBufferSize(lc::MaxFrame * 2);
        s->setLocalCertificate(cert); s->setPrivateKey(key);
        s->setProtocol(QSsl::TlsV1_2OrLater); s->setPeerVerifyMode(QSslSocket::VerifyNone);
        auto p = std::make_shared<Peer>(); peers.insert(s, p);
        connect(s, &QSslSocket::readyRead, this, [this, s, p] {
            if (!p->frames.feed(s->readAll(), [this, s, p](QJsonObject m) { message(s, p, m); })) drop(s);
        });
        connect(s, &QSslSocket::disconnected, this, [this, s, p] {
            if (computers.contains(p->name) && computers[p->name].socket == s) {
                computers[p->name].socket = nullptr; note(p->name + QString::fromUtf8(" відключено"));
            }
            peers.remove(s); s->deleteLater(); refresh();
        });
        s->startServerEncryption();
    }
    void sendUrl(bool all) {
        const auto value = url->text();
        if (!lc::validUrl(value)) {
            QMessageBox::warning(this, "URL", QString::fromUtf8("Введіть коректне посилання http:// або https:// без логіна й пароля.")); return;
        }
        QSet<QString> selected;
        for (auto index : table->selectionModel()->selectedRows()) selected.insert(table->item(index.row(), 0)->text());
        int count = 0;
        for (auto &c : computers) {
            if (!c.socket || QDateTime::currentMSecsSinceEpoch() - c.seen >= lc::OfflineMs ||
                (!all && !selected.contains(c.name))) continue;
            lc::send(c.socket, {{"type", "open"}, {"id", lc::newId()}, {"url", value},
                               {"expires", QDateTime::currentSecsSinceEpoch() + 60}}); ++count;
        }
        note(QString::fromUtf8("Надіслано команд: %1").arg(count));
    }
protected:
    void closeEvent(QCloseEvent *e) override {
        if (exiting || !tray->isVisible()) { e->accept(); QCoreApplication::quit(); }
        else { hide(); e->ignore(); }
    }
public:
    explicit Window(QString path) : base(std::move(path)) {
        setWindowTitle(QString::fromUtf8("LanControl — керування комп’ютерами")); resize(850, 580);
        auto body = new QWidget; setCentralWidget(body); auto layout = new QVBoxLayout(body);
        table = new QTableWidget(0, 3); table->setHorizontalHeaderLabels({QString::fromUtf8("Комп’ютер"), QString::fromUtf8("Стан"), QString::fromUtf8("Версія")});
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::ExtendedSelection); table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        layout->addWidget(table); url = new QLineEdit; url->setPlaceholderText("https://example.org"); layout->addWidget(url);
        auto buttons = new QHBoxLayout;
        for (bool all : {true, false}) {
            auto b = new QPushButton(all ? QString::fromUtf8("Надіслати всім підключеним") : QString::fromUtf8("Надіслати вибраним"));
            buttons->addWidget(b); connect(b, &QPushButton::clicked, this, [this, all] { sendUrl(all); });
        }
        layout->addLayout(buttons); events = new QPlainTextEdit; events->setReadOnly(true); events->setMaximumBlockCount(1000); layout->addWidget(events);
        tray = new QSystemTrayIcon(style()->standardIcon(QStyle::SP_ComputerIcon), this);
        tray->setToolTip("LanControl Server"); auto menu = new QMenu(this);
        menu->addAction(QString::fromUtf8("Відкрити"), this, [this] { showNormal(); raise(); activateWindow(); });
        menu->addAction(QString::fromUtf8("Вийти повністю"), this, [this] { exiting = true; qApp->quit(); });
        tray->setContextMenu(menu); tray->setVisible(QSystemTrayIcon::isSystemTrayAvailable());
        connect(tray, &QSystemTrayIcon::activated, this, [this](auto reason) { if (reason == QSystemTrayIcon::DoubleClick) { showNormal(); activateWindow(); } });
        auto cfg = lc::readJson(base + "/computers.json");
        if (cfg.contains("sharedClientToken")) {
            sharedClientToken = cfg.value("sharedClientToken").toString();
            if (!QRegularExpression("^[a-f0-9]{64}$").match(sharedClientToken).hasMatch())
                throw std::runtime_error("Invalid sharedClientToken in computers.json");
        }
        for (const auto &entry : cfg.value("computers").toArray()) {
            const auto o = entry.toObject(); const auto name = lc::normalizedName(o.value("name").toString());
            const auto token = o.value("token").toString();
            if (!lc::validName(name) || !QRegularExpression("^[a-f0-9]{64}$").match(token).hasMatch() || computers.contains(name))
                throw std::runtime_error("Invalid or duplicate entry in computers.json");
            computers.insert(name, {name, token});
        }
        if (computers.isEmpty()) throw std::runtime_error("computers.json contains no computers");
        for (const auto &c : computers) {
            const int row = table->rowCount(); table->insertRow(row);
            table->setItem(row, 0, new QTableWidgetItem(c.name)); table->setItem(row, 1, new QTableWidgetItem);
            table->setItem(row, 2, new QTableWidgetItem);
        }
        QFile certFile(base + "/server.crt"), keyFile(base + "/server.key");
        if (!certFile.open(QIODevice::ReadOnly) || !keyFile.open(QIODevice::ReadOnly)) throw std::runtime_error("Missing server.crt / server.key");
        cert = QSslCertificate(certFile.readAll(), QSsl::Pem); key = QSslKey(keyFile.readAll(), QSsl::Rsa, QSsl::Pem);
        if (cert.isNull() || key.isNull()) throw std::runtime_error("Invalid TLS certificate/key");
        listener.accepted = [this](qintptr d) { accept(d); };
        if (!listener.listen(QHostAddress::AnyIPv4, lc::Port)) throw std::runtime_error(listener.errorString().toStdString());
        auto timer = new QTimer(this); timer->setInterval(1000);
        connect(timer, &QTimer::timeout, this, [this] {
            const auto now = QDateTime::currentMSecsSinceEpoch();
            const auto copy = peers;
            for (auto it = copy.cbegin(); it != copy.cend(); ++it) {
                const auto &p = it.value();
                if ((p->name.isEmpty() && now - p->born > 10000) ||
                    (!p->name.isEmpty() && now - computers[p->name].seen > lc::OfflineMs)) drop(it.key());
            }
            refresh();
        }); timer->start(); refresh();
        note(QString::fromUtf8("Сервер слухає TCP %1. Список ПК читається під час запуску.").arg(lc::Port));
    }
};
int main(int argc, char **argv) {
    QApplication app(argc, argv); app.setQuitOnLastWindowClosed(false);
    QLockFile lock(QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/LanControl-server.lock");
    if (!lock.tryLock()) return 1;
    if (!QSslSocket::setActiveBackend("openssl") || !QSslSocket::supportsSsl()) {
        QMessageBox::critical(nullptr, "LanControl", "Qt OpenSSL TLS backend is unavailable. Deploy Qt TLS plugins and OpenSSL 3 DLLs."); return 1;
    }
    try {
        QString base = app.arguments().size() > 1 ? app.arguments()[1] : app.applicationDirPath() + "/server-data";
        Window w(base); w.show(); return app.exec();
    } catch (const std::exception &e) { QMessageBox::critical(nullptr, "LanControl", QString::fromUtf8(e.what())); return 1; }
}
