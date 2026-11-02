#!/usr/bin/env python3
"""Run real OpenSSH/kind acceptance on disposable Linux Docker resources.

Requires Docker, kind 0.33+, ssh-keygen, Python 3.10+, and the Rust toolchain.
No existing cluster/context, vault, SSH config, or provider credentials are used.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
UBUNTU = "ubuntu@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3"
SECRET = b"synthetic-cross-node-canary-v1"


def run(argv, *, data=None, env=None, visible=False):
    result = subprocess.run(argv, input=data, stdout=None if visible else subprocess.PIPE,
                            stderr=None if visible else subprocess.PIPE, env=env, cwd=ROOT)
    if result.returncode:
        # Commands can return a bearer token or decrypted Secret; never echo them.
        raise RuntimeError(f"{Path(argv[0]).name} failed (exit {result.returncode})")
    return result.stdout or b""


def docker_id(path):
    """Return the ID Docker wrote after it created a resource, or None when it created nothing."""
    if not path.exists():
        return None
    value = path.read_text().strip()
    if not re.fullmatch(r"(sha256:)?[a-f0-9]{64}", value):
        raise RuntimeError("Docker resource ID file is invalid")
    return value


def kind_nodes(cluster, mount):
    """Return kind node IDs whose bind mount proves this run created them; same-named nodes stay."""
    listed = subprocess.run(["docker", "ps", "-a", "-q", "--no-trunc", "--filter", "label=io.x-k8s.kind.cluster=" + cluster],
                            capture_output=True)
    if listed.returncode:
        return None
    owned = []
    for container in listed.stdout.decode().split():
        if not re.fullmatch(r"[a-f0-9]{64}", container):
            return None
        mounts = subprocess.run(["docker", "container", "inspect", "--format", "{{json .Mounts}}", container], capture_output=True)
        if mounts.returncode:
            return None
        if any(entry.get("Source") == mount and entry.get("Destination") == "/etc/kubernetes/wispkey-encryption.json"
               for entry in json.loads(mounts.stdout)):
            owned.append(container)
    return owned


def cleanup(cluster, scratch):
    nodes = kind_nodes(cluster, str(scratch / "encryption.json"))
    failed = nodes is None
    commands = [["docker", "rm", "-f", "-v", node] for node in nodes or []]
    if container := docker_id(scratch / "ssh.cid"):
        commands.append(["docker", "rm", "-f", "-v", container])
    if image := docker_id(scratch / "image.id"):
        commands.append(["docker", "image", "rm", image])
    for command in commands:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        failed = failed or result.returncode != 0
    if failed:
        raise RuntimeError("cross-node fixture cleanup failed; owned resources require reconciliation")


def write(path, data, mode=0o600):
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    path.chmod(mode)


def main():
    if os.name != "posix":
        raise RuntimeError("run this fixture on Linux (WSL is supported)")
    os.umask(0o077)
    kind = os.environ.get("KIND", "kind")
    for tool in [kind, "docker", "ssh-keygen", "ssh", "cargo"]:
        if not shutil.which(tool):
            raise RuntimeError(f"missing fixture prerequisite: {tool}")
    # CI registries declare exact owned containers, so they pin the suffix; local runs stay random.
    suffix = os.environ.get("WISPKEY_CROSS_NODE_SUFFIX")
    if suffix is None:
        suffix = uuid.uuid4().hex[:12]
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", suffix):
        raise RuntimeError("WISPKEY_CROSS_NODE_SUFFIX must be 1-32 lowercase letters, digits or hyphens")
    cluster, ssh_name = f"wk-accept-{suffix}", f"wk-ssh-{suffix}"
    # kind cannot place its nodes in the shared queue's cgroup; never start an unbounded CI cluster.
    if "CI_BUDGET_CGROUP" in os.environ:
        raise RuntimeError("kind cannot honor CI_BUDGET_CGROUP; cross-node CI requires an approved bounded route")
    with tempfile.TemporaryDirectory(prefix="wk-cross-node-") as directory:
        scratch = Path(directory)
        try:
            print("Building the restricted operation helper...", flush=True)
            run(["cargo", "build", "--locked", "--bin", "wispkey-operation-helper"], visible=True)
            target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
            shutil.copyfile(target / "debug/wispkey-operation-helper", scratch / "helper")
            (scratch / "helper").chmod(0o755)
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(scratch / "identity")])
            write(scratch / "authorized_keys", 'restrict,command="sudo -n /usr/local/libexec/wispkey-operation-helper" '
                  + (scratch / "identity.pub").read_text())
            write(scratch / "fixed-action", '#!/usr/bin/python3\nimport hashlib,sys\n'
                  'value=sys.stdin.buffer.read()\n'
                  f'if hashlib.sha256(value).hexdigest() != "{hashlib.sha256(SECRET).hexdigest()}": sys.exit(9)\n'
                  'with open("/var/lib/wispkey-helper/accepted", "a") as output: output.write("accepted\\n")\n', 0o755)
            write(scratch / "helper.toml", 'version = 1\nprogram = "/usr/local/libexec/wispkey-fixed-action"\nargs = []\n')
            write(scratch / "sudoers", 'wispkey-ssh ALL=(root) NOPASSWD: /usr/local/libexec/wispkey-operation-helper ""\n')
            write(scratch / "sshd_config", 'Port 22\nHostKey /etc/ssh/ssh_host_ed25519_key\n'
                  'PermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n'
                  'PubkeyAuthentication yes\nUsePAM no\nAllowUsers wispkey-ssh\n'
                  'DisableForwarding yes\nPermitTTY no\nLogLevel ERROR\n')
            write(scratch / "Dockerfile", f'''FROM {UBUNTU}
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server sudo python3 ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/sh wispkey-ssh && passwd -d wispkey-ssh && mkdir -p /run/sshd /etc/wispkey /var/lib/wispkey-helper /usr/local/libexec /home/wispkey-ssh/.ssh && chmod 700 /var/lib/wispkey-helper /home/wispkey-ssh/.ssh && ssh-keygen -A
COPY helper /usr/local/libexec/wispkey-operation-helper
COPY fixed-action /usr/local/libexec/wispkey-fixed-action
COPY helper.toml /etc/wispkey/helper.toml
COPY sudoers /etc/sudoers.d/wispkey
COPY sshd_config /etc/ssh/sshd_config
COPY authorized_keys /home/wispkey-ssh/.ssh/authorized_keys
RUN touch /var/lib/wispkey-helper/attempts.db && chmod 600 /var/lib/wispkey-helper/attempts.db && chmod 755 /usr/local/libexec/wispkey-* && chmod 600 /etc/wispkey/helper.toml /home/wispkey-ssh/.ssh/authorized_keys && chmod 440 /etc/sudoers.d/wispkey && chown -R wispkey-ssh:wispkey-ssh /home/wispkey-ssh/.ssh && visudo -cf /etc/sudoers.d/wispkey
CMD ["/usr/sbin/sshd", "-D", "-e"]
''')
            print("Starting loopback-only OpenSSH with a forced helper...", flush=True)
            # Docker writes these ID files only after it creates the resource; cleanup removes only those IDs.
            run(["docker", "buildx", "build", "--provenance=false", "--load", "-q", "--iidfile", str(scratch / "image.id"),
                 "--label", "wispkey.acceptance=" + suffix, str(scratch)])
            image = docker_id(scratch / "image.id")
            if image is None:
                raise RuntimeError("SSH fixture image ID is missing")
            run(["docker", "create", "--cidfile", str(scratch / "ssh.cid"), "--name", ssh_name,
                 "--label", "wispkey.acceptance=" + suffix, "-p", "127.0.0.1::22", image])
            ssh_container = docker_id(scratch / "ssh.cid")
            if ssh_container is None:
                raise RuntimeError("SSH fixture container ID is missing")
            run(["docker", "start", ssh_container])
            port = run(["docker", "port", ssh_container, "22/tcp"]).decode().strip()
            if not port.startswith("127.0.0.1:"):
                raise RuntimeError("SSH fixture did not bind loopback")
            fingerprint = run(["docker", "exec", ssh_container, "ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub", "-E", "sha256"]).decode().split()[1]
            public_key = run(["docker", "exec", ssh_container, "cat", "/etc/ssh/ssh_host_ed25519_key.pub"]).decode().strip()
            write(scratch / "known_hosts", f"[127.0.0.1]:{port.split(':')[1]} {public_key}\n")
            attempt = str(uuid.uuid4())
            hello = {"version":1,"attempt_id":attempt,"phase":"hello","remaining_ms":10000,"deadline_unix_ms":int(time.time()*1000)+10000}
            cancel = {"version":1,"attempt_id":attempt,"phase":"cancel"}
            preflight = subprocess.run(["ssh","-F","/dev/null","-o","BatchMode=yes","-o","IdentitiesOnly=yes",
                "-o","StrictHostKeyChecking=yes","-o","UserKnownHostsFile="+str(scratch / "known_hosts"),
                "-o","ConnectTimeout=5","-i",str(scratch / "identity"),"-p",port.split(':')[1],
                "wispkey-ssh@127.0.0.1","/usr/local/libexec/wispkey-operation-helper"],
                input=(json.dumps(hello)+"\n"+json.dumps(cancel)+"\n").encode(),capture_output=True,timeout=15)
            lines = preflight.stdout.splitlines()
            if not lines or json.loads(lines[0]).get("phase") != "ready":
                raise RuntimeError("SSH helper preflight failed; authentication_denied=" + str(b"Permission denied" in preflight.stderr)
                                   + "; binary_incompatible=" + str(b"GLIBC" in preflight.stderr))

            print("Starting kind with Secret encryption at rest...", flush=True)
            encryption = {"apiVersion":"apiserver.config.k8s.io/v1", "kind":"EncryptionConfiguration",
                          "resources":[{"resources":["secrets"], "providers":[
                              {"aescbc":{"keys":[{"name":"fixture-key", "secret":base64.b64encode(os.urandom(32)).decode()}]}},
                              {"identity":{}}]}]}
            write(scratch / "encryption.json", json.dumps(encryption))
            patch = '''kind: ClusterConfiguration
apiVersion: kubeadm.k8s.io/v1beta4
apiServer:
  extraArgs:
    - name: encryption-provider-config
      value: /etc/kubernetes/wispkey-encryption.json
  extraVolumes:
    - name: wispkey-encryption
      hostPath: /etc/kubernetes/wispkey-encryption.json
      mountPath: /etc/kubernetes/wispkey-encryption.json
      readOnly: true
      pathType: File
'''
            config = {"kind":"Cluster", "apiVersion":"kind.x-k8s.io/v1alpha4",
                      "networking":{"apiServerAddress":"127.0.0.1"},
                      "nodes":[{"role":"control-plane", "kubeadmConfigPatches":[patch], "extraMounts":[{
                          "hostPath":str(scratch / "encryption.json"), "containerPath":"/etc/kubernetes/wispkey-encryption.json", "readOnly":True}]}]}
            write(scratch / "kind.json", json.dumps(config))
            run([kind, "create", "cluster", "--name", cluster, "--config", str(scratch / "kind.json"),
                 "--kubeconfig", str(scratch / "kubeconfig"), "--wait", "120s"], visible=True)
            nodes = kind_nodes(cluster, str(scratch / "encryption.json"))
            if nodes is None or len(nodes) != 1:
                raise RuntimeError("kind fixture node ownership could not be established")
            node = nodes[0]

            def kubectl(*args, data=None):
                return run(["docker", "exec", "-i", node, "kubectl", "--kubeconfig=/etc/kubernetes/admin.conf", *args], data=data)

            resources = [
                {"apiVersion":"v1","kind":"Namespace","metadata":{"name":"wk-acceptance"}},
                {"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"delivery","namespace":"wk-acceptance"}},
                {"apiVersion":"v1","kind":"Secret","metadata":{"name":"selected","namespace":"wk-acceptance","annotations":{"owner":"preserved"}},"type":"Opaque","stringData":{"other":"preserved"}},
                {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"delivery","namespace":"wk-acceptance"},"rules":[{"apiGroups":[""],"resources":["secrets"],"resourceNames":["selected"],"verbs":["get","update"]}]},
                {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"delivery","namespace":"wk-acceptance"},"subjects":[{"kind":"ServiceAccount","name":"delivery","namespace":"wk-acceptance"}],"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"delivery"}},
                {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":"delivery-namespace"},"rules":[{"apiGroups":[""],"resources":["namespaces"],"resourceNames":["wk-acceptance"],"verbs":["get"]}]},
                {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":"delivery-namespace"},"subjects":[{"kind":"ServiceAccount","name":"delivery","namespace":"wk-acceptance"}],"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"delivery-namespace"}},
            ]
            kubectl("apply", "-f", "-", data=json.dumps({"apiVersion":"v1","kind":"List","items":resources}).encode())
            for verb, resource in [("create","secrets"),("list","secrets"),("delete","secrets"),("create","pods")]:
                result = subprocess.run(["docker","exec",node,"kubectl","--kubeconfig=/etc/kubernetes/admin.conf","auth","can-i",verb,resource,"-n","wk-acceptance","--as=system:serviceaccount:wk-acceptance:delivery"], capture_output=True)
                if result.stdout.strip() != b"no" or result.returncode != 1:
                    raise RuntimeError("fixture RBAC is broader than intended")
            raw = kubectl("exec", "-n", "kube-system", "etcd-" + cluster + "-control-plane", "--", "etcdctl",
                          "--cacert=/etc/kubernetes/pki/etcd/ca.crt", "--cert=/etc/kubernetes/pki/etcd/server.crt", "--key=/etc/kubernetes/pki/etcd/server.key",
                          "get", "/registry/secrets/wk-acceptance/selected", "--print-value-only")
            if not raw.startswith(b"k8s:enc:aescbc:v1:"):
                raise RuntimeError("Secret is not encrypted in etcd")
            write(scratch / "provider-token", kubectl("create", "token", "delivery", "-n", "wk-acceptance", "--duration=10m").strip())
            write(scratch / "ca.pem", run(["docker","exec",node,"cat","/etc/kubernetes/pki/ca.crt"]))
            # The in-container config names the container endpoint; Docker publishes loopback.
            api_port = run(["docker","port",node,"6443/tcp"]).decode().strip()
            if not api_port.startswith("127.0.0.1:"):
                raise RuntimeError("Kubernetes fixture did not bind loopback")
            namespace = json.loads(kubectl("get","namespace","wk-acceptance","-o","json"))
            secret = json.loads(kubectl("get","secret","selected","-n","wk-acceptance","-o","json"))
            metadata = {"marker":"wispkey-disposable-cross-node-v1","ssh_port":int(port.split(":")[1]),
                        "ssh_fingerprint":fingerprint,"ssh_identity":str(scratch / "identity"),
                        "endpoint":"https://" + api_port,"namespace_uid":namespace["metadata"]["uid"],
                        "secret_uid":secret["metadata"]["uid"],"ca_file":str(scratch / "ca.pem"),
                        "token_file":str(scratch / "provider-token"),
                        "encryption_revision":hashlib.sha256((scratch / "encryption.json").read_bytes()).hexdigest()}
            write(scratch / "fixture.json", json.dumps(metadata))
            env = dict(os.environ, WISPKEY_TEST_CROSS_NODE_FIXTURE=str(scratch / "fixture.json"))
            print("Running real SSH and Kubernetes transport acceptance...", flush=True)
            run(["cargo","test","--locked","--lib","operations::live_tests::","--","--ignored","--test-threads=1"], env=env, visible=True)
            accepted = run(["docker","exec",ssh_container,"cat","/var/lib/wispkey-helper/accepted"])
            if accepted != b"accepted\n":
                raise RuntimeError("SSH helper did not execute exactly once")
            for argv in [["docker","logs",ssh_container],["docker","logs",node]]:
                result = subprocess.run(argv, capture_output=True)
                if SECRET in result.stdout + result.stderr:
                    raise RuntimeError("synthetic credential appeared in container logs")
            print("PASS: pinned SSH, replay rejection, signed Kubernetes delivery/revocation, narrow RBAC, encrypted etcd.", flush=True)
        finally:
            cleanup(cluster, scratch)


if __name__ == "__main__":
    main()
