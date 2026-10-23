"""Run the standalone client in an empty directory and check its native TLS backend."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--client", type=Path, default=root / "deployment/single-file/LanClient.exe")
parser.add_argument("--probe", type=Path, default=root / "build-standalone-v2/bin/tls_probe.exe")
parser.add_argument("--host", default="127.0.0.1")
args = parser.parse_args()
server = json.loads((root / "deployment/server/server-data/computers.json").read_text(encoding="utf-8-sig"))
client_config = json.loads((root / "deployment/client/client.json").read_text(encoding="utf-8-sig"))
env = os.environ.copy()
env.setdefault("SYSTEMROOT", r"C:\Windows")
env["PATH"] = str(Path(env["SYSTEMROOT"]) / "System32")
for key in ("QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH", "QTDIR"):
    env.pop(key, None)

with tempfile.TemporaryDirectory(prefix="standalone-check-", dir=root / "work") as scratch:
    directory = Path(scratch)
    client = directory / "LanClient.exe"
    shutil.copyfile(args.client, client)
    assert hashlib.sha256(client.read_bytes()).digest() == hashlib.sha256(args.client.read_bytes()).digest()
    completed = subprocess.run([str(client), "--self-test"], cwd=directory, env=env,
                               capture_output=True, text=True, timeout=20,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    assert completed.returncode == 0, (completed.returncode, completed.stderr)
    assert sorted(p.name for p in directory.iterdir()) == ["LanClient.exe"], "Client extracted extra files"
    print("PASS: LanClient.exe runs alone, reads its embedded configuration and loads static Schannel")

    probe = directory / "tls_probe.exe"
    shutil.copyfile(args.probe, probe)
    for computer in server["computers"]:
        completed = subprocess.run([str(probe), args.host, computer["name"]], cwd=directory,
                                   env=env, capture_output=True, text=True, timeout=20)
        assert completed.returncode == 0, (computer["name"], completed.returncode, completed.stderr)
        print(f'PASS: static Schannel TLS, certificate pin, authentication and heartbeat: {computer["name"]}')

    name = server["computers"][0]["name"]
    for extra in (["0" * 64], [client_config["certificateSha256"], "wrong-host.invalid"]):
        completed = subprocess.run([str(probe), args.host, name, *extra], cwd=directory,
                                   env=env, capture_output=True, text=True, timeout=20)
        assert completed.returncode in (5, 6, 9), (completed.returncode, completed.stderr)
    assert not list(directory.glob("*.dll")) and not list(directory.glob("*.json"))
    print("PASS: wrong certificate pin and hostname rejected; no DLL or JSON sidecars needed")
