#include "common.hpp"
#include <QtTest>

class ProtocolTests : public QObject {
    Q_OBJECT
private slots:
    void clientConfiguration() {
        QJsonObject config{{"server", "6kabinet"}, {"port", lc::Port},
                           {"token", QString(64, 'a')}, {"certificateSha256", QString(64, 'b')}};
        QVERIFY(lc::validClientConfig(config));
        auto bad = config; bad.remove("certificateSha256"); QVERIFY(!lc::validClientConfig(bad));
        bad = config; bad["server"] = "other-server"; QVERIFY(!lc::validClientConfig(bad));
        bad = config; bad["port"] = 1; QVERIFY(!lc::validClientConfig(bad));
        bad = config; bad["token"] = ""; QVERIFY(!lc::validClientConfig(bad));
    }
    void urlValidation_data() {
        QTest::addColumn<QString>("input"); QTest::addColumn<bool>("expected");
        QTest::newRow("https") << "https://example.org/lesson?q=one&x=2#chapter" << true;
        QTest::newRow("http-lan") << "http://6kabinet:8080/" << true;
        QTest::newRow("file") << "file:///C:/Windows/System32/cmd.exe" << false;
        QTest::newRow("shell") << "javascript:alert(1)" << false;
        QTest::newRow("credentials") << "https://user:pass@example.org/" << false;
        QTest::newRow("no-host") << "https:///" << false;
        QTest::newRow("newline") << "https://example.org/\n--argument" << false;
        QTest::newRow("backslash") << "https://example.org\\bad" << false;
        QTest::newRow("whitespace") << " https://example.org/" << false;
    }
    void urlValidation() {
        QFETCH(QString, input); QFETCH(bool, expected); QCOMPARE(lc::validUrl(input), expected);
    }
    void fragmentedAndCoalescedFrames() {
        lc::Frames frames; QList<QJsonObject> received;
        auto receive = [&](QJsonObject m) { received.append(m); };
        QVERIFY(frames.feed("{\"type\":\"pi", receive)); QVERIFY(received.isEmpty());
        QVERIFY(frames.feed("ng\"}\n{\"type\":\"pong\"}\n", receive));
        QCOMPARE(received.size(), 2); QCOMPARE(received[0].value("type").toString(), "ping");
        QCOMPARE(received[1].value("type").toString(), "pong");
    }
    void invalidAndOversizedFrames() {
        auto receive = [](QJsonObject) {};
        lc::Frames a; QVERIFY(!a.feed("[]\n", receive));
        lc::Frames b; QVERIFY(!b.feed("{bad}\n", receive));
        lc::Frames c; QVERIFY(!c.feed(QByteArray(lc::MaxFrame + 1, 'a'), receive));
        lc::Frames d; QVERIFY(!d.feed("\n", receive));
    }
    void updateIntegrityAndRollbackPrevention() {
        QTemporaryDir temp; QVERIFY(temp.isValid());
        const QString path = temp.filePath("client.exe");
        QFile f(path); QVERIFY(f.open(QIODevice::WriteOnly)); QCOMPARE(f.write("example-client"), 14); f.close();
        QJsonObject m{{"version", 2}, {"size", 14}, {"sha256", QString::fromLatin1(lc::sha256File(path))}};
        QVERIFY(lc::validManifest(m, 1)); QVERIFY(!lc::validManifest(m, 2)); QVERIFY(!lc::validManifest(m, 3));
        QVERIFY(lc::verifyDownload(path, m));
        QVERIFY(f.open(QIODevice::Append)); f.write("X"); f.close(); QVERIFY(!lc::verifyDownload(path, m));
        m["size"] = 15; QVERIFY(!lc::verifyDownload(path, m)); // same length check is insufficient without hash
        m["size"] = lc::MaxUpdate + 1; QVERIFY(!lc::validManifest(m, 1));
        m["size"] = 14; m["version"] = 2.5; QVERIFY(!lc::validManifest(m, 1));
        m["version"] = 2; m["sha256"] = "../escape"; QVERIFY(!lc::validManifest(m, 1));
    }
    void atomicJson() {
        QTemporaryDir temp; const auto path = temp.filePath("config.json");
        QVERIFY(lc::writeJson(path, {{"version", 1}}));
        QVERIFY(lc::writeJson(path, {{"version", 2}}));
        QCOMPARE(lc::readJson(path).value("version").toInt(), 2);
    }
};
QTEST_GUILESS_MAIN(ProtocolTests)
#include "protocol_tests.moc"
