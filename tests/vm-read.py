# A file in a VM, read whole. Every test that parses or compares a file's
# contents reads it here rather than through machine.succeed("cat ..."):
# succeed's output comes back base64 over the backdoor's virtconsole, and
# QEMU drops a virtconsole's bytes rather than wait when the driver is slow
# to read them (hw/char/virtio-console.c, flush_buf: "silently dropping
# console data on EAGAIN"), so a large file read on a busy host came back
# with whole 4 KiB runs of its base64 missing and failed json.loads. The
# file comes instead through the directory the driver shares with every VM,
# /tmp/shared, which does not drop, and is checked against its sha256 taken
# in the VM, so a torn read fails as one rather than as a parse.
import hashlib as _hashlib
import json as _json
import secrets as _secrets
import shlex as _shlex


def vm_read(m, path):
    name = f"vm-read-{_secrets.token_hex(8)}"
    q = _shlex.quote(path)
    want = m.succeed(f"cat {q} > /tmp/shared/{name} && sha256sum < {q}").split()[0]
    shared = m.shared_dir / name
    try:
        data = shared.read_bytes()
    finally:
        shared.unlink(missing_ok=True)
    got = _hashlib.sha256(data).hexdigest()
    assert got == want, f"{path}: read {len(data)} bytes with sha256 {got}, the VM's is {want}"
    return data.decode()


def vm_json(m, path):
    return _json.loads(vm_read(m, path))
