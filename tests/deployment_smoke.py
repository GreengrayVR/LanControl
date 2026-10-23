"""Exercise the packaged Qt server over real TLS without installing client services."""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--deployment", type=Path, default=root / "deployment")
parser.add_argument("--qt-root", type=Path, default=root / ".build-tools/Qt/6.8.3/msvc2022_64")
args = parser.parse_args()
deployment = args.deployment.resolve()
server = deployment / "server"
data = server / "server-data"
settings = json.loads((data / "computers.json").read_text(encoding="utf-8-sig"))
computers = settings["computers"]
folder = deployment / "client"
config = json.loads((folder / "client.json").read_text(encoding="utf-8-sig"))
assert len({c["token"] for c in computers}) == len(computers)
assert config["token"] == settings["sharedClientToken"]
context = ssl.create_default_context(cafile=str(data / "server.crt"))
der = ssl.PEM_cert_to_DER_cert((data / "server.crt").read_text())
pin = hashlib.sha256(der).hexdigest()
assert config["certificateSha256"] == pin
assert config["server"] == "6kabinet" and config["port"] == 47666
assert not list(folder.rglob("server.key"))
assert not list(folder.rglob("computers.json"))
for name in ("LanClient.exe", "Qt6Core.dll", "Qt6Network.dll", "libssl-3-x64.dll",
             "libcrypto-3-x64.dll", "tls/qopensslbackend.dll"):
    assert (folder / name).is_file(), name
backup = data / "computers.json.before-shared"
if backup.exists():
    original = json.loads(backup.read_text(encoding="utf-8-sig"))
    assert settings["computers"] == original["computers"], "Existing credentials changed"

# Refuse to interfere with a server that is already using this port.
with socket.socket() as probe:
    probe.bind(("127.0.0.1", 47666))

env = os.environ.copy()
env.setdefault("SYSTEMROOT", r"C:\Windows")
env["PATH"] = str(Path(env["SYSTEMROOT"]) / "System32")
env["QT_QPA_PLATFORM"] = "offscreen"
env["QT_QPA_PLATFORM_PLUGIN_PATH"] = str(args.qt_root.resolve() / "plugins/platforms")
env.pop("QT_PLUGIN_PATH", None)
log_path = root / "work/shared-server-smoke.log"
log_path.parent.mkdir(exist_ok=True)
with log_path.open("w", encoding="utf-8") as log:
    process = subprocess.Popen(
        [str(server / "LanServer.exe")], cwd=server, env=env,
        stdout=log, stderr=log, creationflags=subprocess.CREATE_NO_WINDOW,
    )
    try:
        for _ in range(150):
            assert process.poll() is None, "Server exited during startup"
            try:
                with socket.create_connection(("127.0.0.1", 47666), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError(f"Server did not listen on TCP 47666; see {log_path}")

        def connect():
            return context.wrap_socket(
                socket.create_connection(("127.0.0.1", 47666), timeout=5),
                server_hostname="6kabinet",
            )

        def send(stream, message):
            stream.write(json.dumps(message).encode() + b"\n")
            stream.flush()

        def hello(stream, name, token):
            send(stream, dict(type="hello", name=name, token=token, version=1))

        # Keep all PCs connected at once using the exact same client.json credential.
        with ExitStack() as stack:
            streams = []
            for computer in computers:
                connection = stack.enter_context(connect())
                assert hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest() == pin
                stream = stack.enter_context(connection.makefile("rwb"))
                hello(stream, computer["name"].lower(), config["token"])
                assert json.loads(stream.readline())["type"] == "welcome"
                streams.append(stream)
            for computer, stream in zip(computers, streams):
                send(stream, dict(type="ping"))
                assert json.loads(stream.readline())["type"] == "pong"
                send(stream, dict(type="manifest"))
                assert json.loads(stream.readline())["type"] == "no_update"
                print(f'PASS: shared package, simultaneous TLS authentication and heartbeat: {computer["name"]}')

        for computer in computers:
            with connect() as connection, connection.makefile("rwb") as stream:
                hello(stream, computer["name"], computer["token"])
                assert json.loads(stream.readline())["type"] == "welcome"
        print("PASS: existing per-PC credentials still work")

        unknown = "NOT-IN-COMPUTERS"
        assert unknown not in {c["name"] for c in computers}
        rejected = [(computers[0]["name"], "0" * 64), (computers[0]["name"], ""),
                    (unknown, config["token"])]
        if len(computers) > 1:
            rejected.append((computers[0]["name"], computers[1]["token"]))
        for name, token in rejected:
            with connect() as connection, connection.makefile("rwb") as stream:
                hello(stream, name, token)
                assert stream.readline() == b"", "Unauthorized connection was accepted"
        print("PASS: wrong/empty tokens, unknown PC and mismatched legacy credential rejected")
        print("PASS: common configuration, certificate pin, bundled dependencies and migration verified")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
