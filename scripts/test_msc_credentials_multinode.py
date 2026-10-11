#!/usr/bin/env python3
"""Test credential renewal and IKE authentication across two disposable worker fixtures.

Requires SSH/sudo to two Linux Docker workers, the same updated Twinet binary on
both, a shared underlay, and python3-cryptography on the authority. Existing MSC
containers are untouched. Only the test's named resources and temporary SSH key
are removed. Public results are saved locally; CA/device private keys stay on
their assigned machines and are deleted with the test fixture.
"""
import argparse
import datetime
import json
from pathlib import Path
import secrets
import shlex
import subprocess
import tempfile


#* Reuse two authenticated SSH connections during the many short test commands.
SSH_CONTROL = tempfile.TemporaryDirectory(prefix="msc-ssh-", dir="/tmp")
SSH_SOCKET = SSH_CONTROL.name + "/%C"


def remote(host, args, data=None, check=True):
    result = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2",
                             "-o", "ControlMaster=auto", "-o", "ControlPersist=60", "-o", "ControlPath=" + SSH_SOCKET, host, shlex.join([str(a) for a in args])],
                            input=data, stdin=subprocess.DEVNULL if data is None else None,
                            text=True, capture_output=True, timeout=180)
    if check and result.returncode:
        raise RuntimeError(f"{host}: {args[0]} failed: {result.stderr[-1800:]} {result.stdout[-1800:]}")
    return result


def put(host, path, data):
    program = "import os,pathlib,sys;p=pathlib.Path(sys.argv[1]);p.parent.mkdir(parents=True,exist_ok=True,mode=0o700);p.write_text(sys.stdin.read());os.chmod(p,0o600)"
    remote(host, ["sudo", "-n", "python3", "-c", program, path], data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authority", required=True)
    parser.add_argument("--worker", required=True)
    parser.add_argument("--authority-ip", required=True)
    parser.add_argument("--worker-ip", required=True)
    parser.add_argument("--underlay-interface", default="eno2")
    parser.add_argument("--binary", default="/usr/local/libexec/twinet-msc-credentials")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    tag = secrets.token_hex(3)
    lab, net, bridge, vx = "credtest-" + tag, "crednet-" + tag, "crlbr" + tag, "crlvx" + tag
    state = "/var/lib/twinet/credential-test-" + tag
    ids = ["AUTH_A_" + tag, "AUTH_B_" + tag]
    hosts = [args.authority, args.worker]
    outside = ["192.0.2.2", "192.0.2.3"]
    vni = 10000000 + int(tag, 16) % 5000000
    image = json.loads((Path(__file__).resolve().parent.parent / "examples/msc/msc.json").read_text())["image"]
    spec = {"version": 2, "name": lab, "image": image, "router_image": image, "switch_image": image, "mtu": 1400, "devices": [], "links": []}
    for i in range(2):
        red, peer_red = f"10.253.{21+i}", f"10.253.{22-i}"
        host_id = "END_" + str(i) + "_" + tag
        spec["devices"].append({"id": ids[i], "role": "inner", "site": "AB"[i], "level": "S1",
                                "interfaces": [{"name": "red", "address": red + ".1/24", "zone": "red"}, {"name": "eth0", "address": outside[i] + "/29", "zone": "gray"}],
                                "tunnel": {"peer": ids[1-i], "local": outside[i], "remote": outside[1-i], "local_ts": red + ".0/24", "remote_ts": peer_red + ".0/24",
                                           "trust": "credential-test", "reqid": 101 + i, "inside": "red", "outside": "eth0"}})
        spec["devices"].append({"id": host_id, "role": "host", "site": "AB"[i], "level": "S1", "interfaces": [{"name": "red", "address": red + ".2/24", "zone": "red"}]})
        spec["links"].append({"a": {"device": ids[i], "interface": "red"}, "b": {"device": host_id, "interface": "red"}})
    spec["links"].append({"a": {"device": ids[0], "interface": "eth0"}, "b": {"device": ids[1], "interface": "eth0"}})
    plan = {"workers": [{"name": "site-a", "state_dir": state, "devices": [ids[0]]},
                        {"name": "site-b", "ssh": args.worker.split("@", 1)[0] + "@" + args.worker_ip, "binary": args.binary, "state_dir": state, "devices": [ids[1]],
                         "identity_file": state + "/ssh_key", "known_hosts_file": state + "/known_hosts"}]}
    base = ["sudo", "-n", args.binary, "msc", "--spec", state + "/spec.json", "--state-dir", state]
    created = {h: {"containers": [], "network": False, "vxlan": False, "state": False} for h in hosts}
    public_key = None
    authorized_installed = False
    timer_installed = False
    results = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "lab": lab, "checks": [], "passed": False}

    def record(name, condition):
        results["checks"].append({"name": name, "passed": bool(condition)})
        print(name + ": " + ("PASS" if condition else "FAIL"), flush=True)
        if not condition:
            raise RuntimeError(name)

    def renew(*extra, check=True):
        result = remote(args.authority, [*base, "credentials", "renew", "--targets", state + "/targets.json", *extra], check=check)
        if result.stdout.strip():
            results["last_renewal"] = json.loads(result.stdout)
        return result

    def swan(i, *command, check=True):
        return remote(hosts[i], ["sudo", "-n", "timeout", "30", "docker", "exec", ids[i], "timeout", "25", "swanctl", *command], check=check)

    def reconnect(expect, reload=False):
        for i in range(2):
            swan(i, "--terminate", "--ike", "msc", check=False)
        if reload:
            for i in range(2):
                swan(i, "--load-all", "--clear")
        result = swan(0, "--initiate", "--child", "protected", "--timeout", "12", check=False)
        record(expect, result.returncode == 0 if "accepted" in expect else result.returncode != 0)
        if "rejected" in expect:
            logs = "".join(remote(hosts[i], ["sudo", "-n", "docker", "exec", ids[i], "tail", "-n", "80", "/tmp/charon.log"]).stdout for i in range(2))
            results.setdefault("rejection_logs", {})[expect] = {"daemon_log": logs, "client_stdout": result.stdout, "client_stderr": result.stderr}
            reason = "crl is stale" if "expired CRL" in expect else "certificate was revoked"
            record("rejection log confirms " + reason, reason in logs)

    try:
        for host in hosts:
            remote(host, ["sudo", "-n", "test", "!", "-e", state])
            remote(host, ["sudo", "-n", "mkdir", "-m", "0700", state])
            created[host]["state"] = True
            for device in ids:
                if remote(host, ["sudo", "-n", "docker", "inspect", device], check=False).returncode == 0:
                    raise RuntimeError("Refusing existing test container")
        put(args.authority, state + "/spec.json", json.dumps(spec))
        put(args.authority, state + "/targets.json", json.dumps(plan))
        put(args.authority, state + "/fixture.py", (Path(__file__).parent / "testdata/msc_credential_fixture.py").read_text())
        remote(args.authority, ["sudo", "-n", "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", state + "/ssh_key"])
        public_key = remote(args.authority, ["sudo", "-n", "cat", state + "/ssh_key.pub"]).stdout.strip()
        host_key = remote(args.worker, ["cat", "/etc/ssh/ssh_host_ed25519_key.pub"]).stdout.strip()
        put(args.authority, state + "/known_hosts", args.worker_ip + " " + host_key + "\n")
        authorized = 'restrict,from="' + args.authority_ip + '" ' + public_key
        auth_program = "from pathlib import Path;import os,sys;p=Path.home()/'.ssh/authorized_keys';p.parent.mkdir(exist_ok=True,mode=0o700);old=p.read_text() if p.exists() else '';p.write_text(old.rstrip('\\n')+'\\n'+sys.argv[1]+'\\n');os.chmod(p,0o600)"
        remote(args.worker, ["python3", "-c", auth_program, authorized])
        authorized_installed = True
        renew("--provision-only")
        record("worker receives no CA private directory", remote(args.worker, ["sudo", "-n", "test", "!", "-e", state + "/ca"], check=False).returncode == 0)
        record("worker receives no other endpoint key", remote(args.worker, ["sudo", "-n", "test", "!", "-e", state + "/devices/" + ids[0]], check=False).returncode == 0)
        for i, host in enumerate(hosts):
            remote(host, ["sudo", "-n", "docker", "network", "create", "--label", "twinet.credential-test=" + lab, "--subnet", "192.0.2.0/29", "--gateway", "192.0.2." + ("1" if i == 0 else "6"), "-o", "com.docker.network.bridge.name=" + bridge, net])
            created[host]["network"] = True
            remote(host, ["sudo", "-n", "ip", "link", "add", vx, "type", "vxlan", "id", str(vni), "local", [args.authority_ip, args.worker_ip][i], "remote", [args.worker_ip, args.authority_ip][i], "dev", args.underlay_interface, "dstport", "4789"])
            created[host]["vxlan"] = True
            remote(host, ["sudo", "-n", "ip", "link", "set", vx, "master", bridge])
            remote(host, ["sudo", "-n", "ip", "link", "set", vx, "up"])
            remote(host, ["sudo", "-n", "docker", "run", "-d", "--name", ids[i], "--network", net, "--ip", outside[i], "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
                          "--label", "twinet.msc.lab=" + lab, "--label", "twinet.msc.state=" + state, "--label", "twinet.credential-test=" + lab,
                          "-v", state + "/devices/" + ids[i] + "/swanctl:/etc/swanctl:ro", "--entrypoint", "/bin/sh", image, "-c", "sleep infinity"])
            created[host]["containers"].append(ids[i])
            for command in [["ip", "link", "add", "red", "type", "dummy"], ["ip", "addr", "add", f"10.253.{21+i}.1/24", "dev", "red"], ["ip", "link", "set", "red", "up"],
                            ["ip", "route", "add", f"10.253.{22-i}.0/24", "via", outside[1-i]], ["sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"]]:
                remote(host, ["sudo", "-n", "docker", "exec", ids[i], *command])
        renew()
        reconnect("cross-node certificate authentication accepted")
        record("encrypted cross-node ping", remote(args.authority, ["sudo", "-n", "docker", "exec", ids[0], "ping", "-I", "10.253.21.1", "-c", "2", "-W", "3", "10.253.22.1"], check=False).returncode == 0)
        remote(args.authority, ["sudo", "-n", "python3", state + "/fixture.py", state, "expire-crl", ids[1]])
        stale = remote(args.authority, ["sudo", "-n", "cat", state + "/ca/credential-test/crl.pem"]).stdout
        put(args.worker, state + "/devices/" + ids[1] + "/swanctl/x509crl/ca.crl.pem", stale)
        reconnect("expired CRL authentication rejected", reload=True)
        renew()
        reconnect("renewed CRL authentication accepted")
        crl_text = remote(args.worker, ["sudo", "-n", "openssl", "crl", "-in", state + "/devices/" + ids[1] + "/swanctl/x509crl/ca.crl.pem", "-text", "-noout"]).stdout
        record("revoked serial survives expired CRL repair", "067932" in crl_text)
        remote(args.authority, ["sudo", "-n", "python3", state + "/fixture.py", state, "age-leaf", ids[1]])
        renew()
        reconnect("renewed device certificate authentication accepted")
        remote(args.authority, ["sudo", "-n", "python3", state + "/fixture.py", state, "revoke-retired", ids[1]])
        renew("--force")
        retired = remote(args.authority, ["sudo", "-n", "cat", state + "/retired-leaf.pem"]).stdout
        put(args.worker, state + "/devices/" + ids[1] + "/swanctl/x509/cert.pem", retired)
        reconnect("revoked certificate authentication rejected", reload=True)
        renew()
        reconnect("current certificate authentication accepted after revocation test")
        remote(args.authority, [*base, "credentials", "install-timer", "--targets", state + "/targets.json"])
        timer_installed = True
        remote(args.authority, ["sudo", "-n", "systemctl", "start", "twinet-msc-credentials-" + lab + ".service"])
        service = remote(args.authority, ["sudo", "-n", "systemctl", "show", "twinet-msc-credentials-" + lab + ".service", "-p", "Result", "-p", "ExecMainStatus"]).stdout
        record("cross-node renewal succeeds from systemd", "Result=success" in service and "ExecMainStatus=0" in service)
        results["passed"] = True
    except Exception as error:
        results["error"] = str(error)
        raise
    finally:
        cleanup_errors = []
        for host in hosts:
            if host == args.authority and timer_installed:
                name = "twinet-msc-credentials-" + lab
                remote(host, ["sudo", "-n", "systemctl", "disable", "--now", name + ".timer"], check=False)
                remote(host, ["sudo", "-n", "systemctl", "stop", name + ".service"], check=False)
                program = "from pathlib import Path;import sys;[(Path('/etc/systemd/system')/(sys.argv[1]+s)).unlink(missing_ok=True) for s in ['.timer','.service']]"
                remote(host, ["sudo", "-n", "python3", "-c", program, name], check=False)
                remote(host, ["sudo", "-n", "systemctl", "daemon-reload"], check=False)
            for device in created[host]["containers"]:
                result = remote(host, ["sudo", "-n", "docker", "rm", "-f", device], check=False)
                if result.returncode:
                    cleanup_errors.append(host + ": container " + device)
            if created[host]["vxlan"]:
                if remote(host, ["sudo", "-n", "ip", "link", "delete", vx], check=False).returncode:
                    cleanup_errors.append(host + ": VXLAN " + vx)
            if created[host]["network"]:
                result = remote(host, ["sudo", "-n", "docker", "network", "rm", net], check=False)
                if result.returncode:
                    cleanup_errors.append(host + ": network " + net)
            if created[host]["state"]:
                if remote(host, ["sudo", "-n", "python3", "-c", "import shutil,sys;shutil.rmtree(sys.argv[1])", state], check=False).returncode:
                    cleanup_errors.append(host + ": private state " + state)
        if authorized_installed:
            program = "from pathlib import Path;import sys;p=Path.home()/'.ssh/authorized_keys';p.write_text(''.join(line for line in p.read_text().splitlines(True) if sys.argv[1] not in line))"
            if remote(args.worker, ["python3", "-c", program, public_key], check=False).returncode:
                cleanup_errors.append("temporary SSH authorization")
        results["cleanup_errors"] = cleanup_errors
        results["passed"] = results["passed"] and not cleanup_errors
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(results, indent=2) + "\n")
        for host in hosts:
            subprocess.run(["ssh", "-S", SSH_SOCKET, "-O", "exit", host], stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
        SSH_CONTROL.cleanup()
    if not results["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
