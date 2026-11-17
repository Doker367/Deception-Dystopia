#!/usr/bin/env python3
"""Build-time patch: make Cowrie's ``/proc/self`` coherent and realistic.

The upstream Cowrie image serves a synthetic 336-byte ELF for an executable
file with no stored contents.  That is a strong fingerprint: ``cat
/proc/self/exe`` is expected to return the real executable of the command that
is reading it.

This patch does three things at image-build time:

1. Adds real, benign binaries to ``honeyfs`` (the Dockerfile copies them from
   a pinned Debian build stage): cat, coreutils readers, mawk, tar, python and
   a static busybox.  They are only served as file bytes; none of them is run
   from ``honeyfs``.
2. Adds ``/usr/bin/busybox`` to Cowrie's fake filesystem so ``init_honeyfs``
   can bind the real file to it.
3. Teaches Cowrie's shell/filesystem to resolve ``/proc/self/exe``,
   ``/proc/self/cmdline`` and ``/proc/self/comm`` from the command currently
   executing, instead of always returning the fixed ``/proc/969`` Python
   process.  ``ls -l /proc/self/exe`` is adjusted too.

The script is deliberately fail-closed: if an upstream file no longer matches
an expected anchor, the image build fails instead of silently shipping a
half-patched honeypot.
"""

from __future__ import annotations

import os
import pickle
import posixpath
import stat
import sys
import time
from pathlib import Path

COWRIE_SRC = Path(os.environ.get("COWRIE_SRC", "/cowrie/cowrie-git/src/cowrie"))
COWRIE_FS = Path(os.environ.get("COWRIE_FS", str(COWRIE_SRC / "data" / "fs.pickle")))
HONEYFS = Path(os.environ.get("COWRIE_HONEYFS", "/cowrie/cowrie-git/share/cowrie/honeyfs"))

# Indices used by cowrie.shell.fs.  Kept local so the build patch does not
# import a package before it has been validated.
A_NAME = 0
A_TYPE = 1
A_UID = 2
A_GID = 3
A_SIZE = 4
A_MODE = 5
A_CTIME = 6
A_CONTENTS = 7
A_TARGET = 8
A_REALFILE = 9
T_DIR = 1
T_FILE = 2

# Real files copied into honeyfs by the Dockerfile.  Each must exist and be a
# reasonable size, otherwise the image would still contain a fake executable.
REAL_FILES = (
    "usr/bin/base64",
    "usr/bin/busybox",
    "usr/bin/cat",
    "usr/bin/cut",
    "usr/bin/dd",
    "usr/bin/mawk",
    "usr/bin/python3.11",
    "usr/bin/sed",
    "usr/bin/tar",
    "usr/bin/wc",
)

# Keep these constants in sync with runtime/canary.py.  The canary is content
# inside the fake filesystem, never a callback or a tracker.
CANARY_ID = "finance-2026"
CANARY_PATH = "/srv/files/finance/2026-q4.csv"
CANARY_TOKEN = "DYSTOPIA-CANARY-FINANCE-2026-7F3C9A2E"
CANARY_CONTENT = (
    "period,account,amount,currency,reference\n"
    "2026-Q4,ACME-041,184250.00,USD,INV-2026-1041\n"
    "2026-Q4,ACME-042,98210.50,USD,INV-2026-1042\n"
    "2026-Q4,NORTHWIND-017,55120.00,USD,DYSTOPIA-CANARY-FINANCE-2026-7F3C9A2E\n"
    "2026-Q4,CONTOSO-003,120400.75,USD,INV-2026-1044\n"
)


def fail(message: str) -> None:
    print(f"cowrie patch: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        fail(f"{label}: expected exactly one anchor, found {count}")
    return source.replace(old, new, 1)


def write_python(path: Path, source: str) -> None:
    # Compile before writing so a bad replacement cannot leave a broken image.
    compile(source, str(path), "exec")
    path.write_text(source, encoding="utf-8")


def node_at(root: list, path: str) -> list | None:
    node = root
    for part in (piece for piece in path.strip("/").split("/") if piece):
        if not isinstance(node, list) or node[A_TYPE] != T_DIR:
            return None
        for child in node[A_CONTENTS]:
            if child[A_NAME] == part:
                node = child
                break
        else:
            return None
    return node


def add_busybox_node(root: list) -> None:
    usr_bin = node_at(root, "/usr/bin")
    if usr_bin is None:
        fail("/usr/bin missing from fs.pickle")
    size = (HONEYFS / "usr/bin/busybox").stat().st_size
    for child in usr_bin[A_CONTENTS]:
        if child[A_NAME] == "busybox":
            child[A_SIZE] = size
            child[A_MODE] = stat.S_IFREG | 0o755
            break
    else:
        usr_bin[A_CONTENTS].append(
            [
                "busybox",
                T_FILE,
                0,
                0,
                size,
                stat.S_IFREG | 0o755,
                time.time(),
                [],
                None,
                None,
            ]
        )


def ensure_dir(root: list, path: str) -> list:
    node = root
    for part in (piece for piece in path.strip("/").split("/") if piece):
        if node[A_TYPE] != T_DIR:
            fail(f"{path}: parent is not a directory")
        for child in node[A_CONTENTS]:
            if child[A_NAME] == part:
                node = child
                break
        else:
            child = [
                part,
                T_DIR,
                0,
                0,
                4096,
                stat.S_IFDIR | 0o755,
                time.time(),
                [],
                None,
                None,
            ]
            node[A_CONTENTS].append(child)
            node = child
    return node


def add_canary_file(root: list) -> None:
    parent = ensure_dir(root, posixpath.dirname(CANARY_PATH))
    name = posixpath.basename(CANARY_PATH)
    content = CANARY_CONTENT.encode("utf-8")
    parent[A_CONTENTS] = [child for child in parent[A_CONTENTS] if child[A_NAME] != name]
    parent[A_CONTENTS].append(
        [
            name,
            T_FILE,
            0,
            0,
            len(content),
            stat.S_IFREG | 0o644,
            time.time(),
            content,
            None,
            None,
        ]
    )


def patch_fs_pickle() -> None:
    if not COWRIE_FS.is_file():
        fail(f"{COWRIE_FS} does not exist")
    with COWRIE_FS.open("rb") as fh:
        root = pickle.load(fh)
    if not isinstance(root, list):
        fail("fs.pickle root is not a Cowrie node")
    add_busybox_node(root)
    add_canary_file(root)
    # Preserve the upstream pickle protocol; Cowrie reads it with pickle.load.
    with COWRIE_FS.open("wb") as fh:
        pickle.dump(root, fh, protocol=4)


def patch_fs_py() -> None:
    path = COWRIE_SRC / "shell" / "fs.py"
    source = read_text(path)

    source = replace_once(
        source,
        "        self.arch: str = arch\n        self.home: str = home\n",
        (
            "        self.arch: str = arch\n"
            "        self.home: str = home\n"
            "\n"
            "        # The executable of the command currently reading a\n"
            "        # process-relative /proc entry.  Shell commands are\n"
            "        # synchronous in Cowrie, so one slot is enough; nested\n"
            "        # execs (busybox) overwrite it before reading.\n"
            "        self.current_exe: str | None = None\n"
            "        self.current_argv: list[str] = []\n"
        ),
        "fs.py current process state",
    )

    source = replace_once(
        source,
        "            f[A_REALFILE] = realfile\n",
        (
            "            f[A_REALFILE] = realfile\n"
            "            # Keep ls/stat metadata in step with the bytes served.\n"
            "            f[A_SIZE] = os.path.getsize(realfile)\n"
        ),
        "fs.py realfile size",
    )

    source = replace_once(
        source,
        (
            "        path: str = self.resolve_path(target, posixpath.dirname(target))\n"
            "        if not path or not self.exists(path):\n"
        ),
        (
            "        path: str = self.resolve_path(target, posixpath.dirname(target))\n"
            "\n"
            "        # /proc/self is process-relative.  Cowrie has a fixed fake\n"
            "        # process (/proc/969), so answer the common entries from the\n"
            "        # command that is actually running.\n"
            "        if path in (\"/proc/self/exe\", \"/proc/thread-self/exe\"):\n"
            "            exe = self.current_exe\n"
            "            if exe:\n"
            "                return self.file_contents(exe)\n"
            "        if path in (\"/proc/self/cmdline\", \"/proc/thread-self/cmdline\"):\n"
            "            argv = self.current_argv\n"
            "            if argv:\n"
            "                return (\n"
            "                    b\"\\0\".join(arg.encode(\"utf-8\", \"replace\") for arg in argv)\n"
            "                    + b\"\\0\"\n"
            "                )\n"
            "        if path in (\"/proc/self/comm\", \"/proc/thread-self/comm\"):\n"
            "            exe = self.current_exe\n"
            "            if exe:\n"
            "                return (posixpath.basename(exe) + \"\\n\").encode()\n"
            "        if path in (\"/proc/self/status\", \"/proc/thread-self/status\"):\n"
            "            exe = self.current_exe or \"/usr/bin/python3.11\"\n"
            "            name = posixpath.basename(exe)\n"
            "            return (\n"
            "                f\"Name:\\t{name}\\n\"\n"
            "                \"Umask:\\t0022\\n\"\n"
            "                \"State:\\tR (running)\\n\"\n"
            "                \"Tgid:\\t969\\n\"\n"
            "                \"Ngid:\\t0\\n\"\n"
            "                \"Pid:\\t969\\n\"\n"
            "                \"PPid:\\t1\\n\"\n"
            "                \"TracerPid:\\t0\\n\"\n"
            "                \"Uid:\\t0\\t0\\t0\\t0\\n\"\n"
            "                \"Gid:\\t0\\t0\\t0\\t0\\n\"\n"
            "                \"FDSize:\\t64\\n\"\n"
            "                \"Groups:\\t0\\n\"\n"
            "                \"VmPeak:\\t   14336 kB\\n\"\n"
            "                \"VmSize:\\t   14336 kB\\n\"\n"
            "                \"VmHWM:\\t    4096 kB\\n\"\n"
            "                \"VmRSS:\\t    4096 kB\\n\"\n"
            "                \"RssAnon:\\t    1024 kB\\n\"\n"
            "                \"RssFile:\\t    3072 kB\\n\"\n"
            "                \"VmData:\\t    1024 kB\\n\"\n"
            "                \"VmStk:\\t     132 kB\\n\"\n"
            "                \"VmExe:\\t      44 kB\\n\"\n"
            "                \"VmLib:\\t    2048 kB\\n\"\n"
            "                \"VmPTE:\\t      40 kB\\n\"\n"
            "                \"Threads:\\t1\\n\"\n"
            "                \"SigQ:\\t0/12345\\n\"\n"
            "                \"SigPnd:\\t0000000000000000\\n\"\n"
            "                \"ShdPnd:\\t0000000000000000\\n\"\n"
            "                \"SigBlk:\\t0000000000000000\\n\"\n"
            "                \"SigIgn:\\t0000000000000000\\n\"\n"
            "                \"SigCgt:\\t0000000000000000\\n\"\n"
            "                \"CapInh:\\t0000000000000000\\n\"\n"
            "                \"CapPrm:\\t0000000000000000\\n\"\n"
            "                \"CapEff:\\t0000000000000000\\n\"\n"
            "                \"CapBnd:\\t0000000000000000\\n\"\n"
            "                \"CapAmb:\\t0000000000000000\\n\"\n"
            "                \"NoNewPrivs:\\t0\\n\"\n"
            "                \"Seccomp:\\t0\\n\"\n"
            "                \"Cpus_allowed:\\t1\\n\"\n"
            "                \"Cpus_allowed_list:\\t0\\n\"\n"
            "                \"Mems_allowed:\\t1\\n\"\n"
            "                \"Mems_allowed_list:\\t0\\n\"\n"
            "                \"voluntary_ctxt_switches:\\t0\\n\"\n"
            "                \"nonvoluntary_ctxt_switches:\\t0\\n\"\n"
            "            ).encode()\n"
            "        if path in (\"/proc/self/maps\", \"/proc/thread-self/maps\"):\n"
            "            exe = self.current_exe or \"/usr/bin/python3.11\"\n"
            "            return (\n"
            "                f\"00400000-0040b000 r--p 00000000 fd:01 123456 {exe}\\n\"\n"
            "                f\"0040b000-0040c000 r-xp 0000b000 fd:01 123456 {exe}\\n\"\n"
            "                f\"0040c000-0040d000 r--p 0000c000 fd:01 123456 {exe}\\n\"\n"
            "                f\"0040d000-0040e000 rw-p 0000d000 fd:01 123456 {exe}\\n\"\n"
            "                \"0060e000-0062f000 rw-p 00000000 00:00 0 [heap]\\n\"\n"
            "                \"7ffff7d8a000-7ffff7f4a000 r-xp 00000000 fd:01 654321 /usr/lib/x86_64-linux-gnu/libc.so.6\\n\"\n"
            "                \"7ffff7f4a000-7ffff814a000 ---p 001c0000 fd:01 654321 /usr/lib/x86_64-linux-gnu/libc.so.6\\n\"\n"
            "                \"7ffff814a000-7ffff814e000 r--p 001c0000 fd:01 654321 /usr/lib/x86_64-linux-gnu/libc.so.6\\n\"\n"
            "                \"7ffff814e000-7ffff8150000 rw-p 001c4000 fd:01 654321 /usr/lib/x86_64-linux-gnu/libc.so.6\\n\"\n"
            "                \"7ffff8150000-7ffff8154000 rw-p 00000000 00:00 0\\n\"\n"
            "                \"7ffff8154000-7ffff8156000 r--p 00000000 00:00 0 [vvar]\\n\"\n"
            "                \"7ffff8156000-7ffff8158000 r-xp 00000000 00:00 0 [vdso]\\n\"\n"
            "                \"7ffff8158000-7ffff8179000 r--p 00000000 00:00 0 [stack]\\n\"\n"
            "            ).encode()\n"
            "        if not path or not self.exists(path):\n"
        ),
        "fs.py process-relative proc entries",
    )

    write_python(path, source)


def patch_protocol_py() -> None:
    path = COWRIE_SRC / "shell" / "protocol.py"
    source = read_text(path)

    source = replace_once(
        source,
        (
            "    def call_command(self, pp, cmd, *args):\n"
            "        \"\"\"Run a command with the stdio wiring ``pp``. A command that runs\n"
        ),
        (
            "    def _resolve_exec_path(self, pp):\n"
            "        \"\"\"Resolve argv0 to the fake-fs path of the executable.\"\"\"\n"
            "        argv0 = getattr(pp, \"argv0\", None)\n"
            "        if not argv0:\n"
            "            return None\n"
            "        cwd = getattr(pp, \"cwd\", \"/\")\n"
            "        if \"/\" in argv0:\n"
            "            return self.fs.resolve_path(argv0, cwd)\n"
            "        shell = self.cmdstack[-1] if self.cmdstack else None\n"
            "        environ = getattr(shell, \"environ\", {}) or {}\n"
            "        search = environ.get(\n"
            "            \"PATH\", \"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n"
            "        )\n"
            "        for directory in search.split(\":\"):\n"
            "            candidate = self.fs.resolve_path(f\"{directory}/{argv0}\", cwd)\n"
            "            if self.fs.exists(candidate):\n"
            "                return candidate\n"
            "        return self.fs.resolve_path(argv0, cwd)\n"
            "\n"
            "    def call_command(self, pp, cmd, *args):\n"
            "        \"\"\"Run a command with the stdio wiring ``pp``. A command that runs\n"
        ),
        "protocol.py exec resolver",
    )

    source = replace_once(
        source,
        (
            "        another synchronously during ``start()`` (``su -c``, ``sh -c``, a\n"
            "        nested shell, busybox) reaches back here and executes it inline.\"\"\"\n"
            "        self.pp = pp\n"
        ),
        (
            "        another synchronously during ``start()`` (``su -c``, ``sh -c``, a\n"
            "        nested shell, busybox) reaches back here and executes it inline.\"\"\"\n"
            "        if not getattr(pp, \"exec_path\", None):\n"
            "            pp.exec_path = self._resolve_exec_path(pp)\n"
            "        self.fs.current_exe = pp.exec_path\n"
            "        self.fs.current_argv = (\n"
            "            [pp.argv0]\n"
            "            if getattr(pp, \"argv0\", None)\n"
            "            else [pp.exec_path or cmd.__name__]\n"
            "        ) + list(args)\n"
            "        self.pp = pp\n"
        ),
        "protocol.py current executable",
    )

    write_python(path, source)


def patch_command_py() -> None:
    path = COWRIE_SRC / "shell" / "command.py"
    source = read_text(path)

    source = replace_once(
        source,
        (
            "        pp: Any = getattr(self.protocol, \"pp\", None)\n"
            "        self.pp: Any = pp\n"
        ),
        (
            "        pp: Any = getattr(self.protocol, \"pp\", None)\n"
            "        self.pp: Any = pp\n"
            "        # Filled by the protocol at spawn; propagated by wrapper\n"
            "        # commands such as busybox when they exec an applet.\n"
            "        self.exec_path: str | None = getattr(pp, \"exec_path\", None)\n"
        ),
        "command.py exec path",
    )

    source = replace_once(
        source,
        "    def exec_command(self, pp: Any, cmdclass: Any, *args: str) -> None:\n",
        (
            "    def exec_command(\n"
            "        self,\n"
            "        pp: Any,\n"
            "        cmdclass: Any,\n"
            "        *args: str,\n"
            "        inherit_exec_path: bool = False,\n"
            "    ) -> None:\n"
        ),
        "command.py exec signature",
    )

    source = replace_once(
        source,
        (
            "        self.exited = True\n"
            "        if self in self.protocol.cmdstack:\n"
            "            self.protocol.cmdstack.remove(self)\n"
            "        self.protocol.call_command(pp, cmdclass, *args)\n"
        ),
        (
            "        self.exited = True\n"
            "        if self in self.protocol.cmdstack:\n"
            "            self.protocol.cmdstack.remove(self)\n"
            "        # busybox changes argv[0] in the same process image; sudo\n"
            "        # execs a new image, so only busybox inherits the path.\n"
            "        if inherit_exec_path and self.exec_path:\n"
            "            pp.exec_path = self.exec_path\n"
            "            pp.argv0 = self.exec_path\n"
            "        self.protocol.call_command(pp, cmdclass, *args)\n"
        ),
        "command.py exec propagation",
    )

    write_python(path, source)


def patch_busybox_py() -> None:
    path = COWRIE_SRC / "commands" / "busybox.py"
    source = read_text(path)

    source = replace_once(
        source,
        "        self.exec_command(pp, cmdclass, *self.args[1:])\n",
        (
            "        self.exec_command(\n"
            "            pp, cmdclass, *self.args[1:], inherit_exec_path=True\n"
            "        )\n"
        ),
        "busybox.py exec path inheritance",
    )

    write_python(path, source)


def patch_sudo_py() -> None:
    path = COWRIE_SRC / "commands" / "sudo.py"
    source = read_text(path)

    source = replace_once(
        source,
        (
            "                pp.stdin_from_pipe = self.pp.stdin_from_pipe\n"
            "                self.exec_command(pp, cmdclass, *parsed_arguments[1:])\n"
        ),
        (
            "                pp.stdin_from_pipe = self.pp.stdin_from_pipe\n"
            "                # sudo execs the target as a new image; resolve the\n"
            "                # target's own path instead of inheriting sudo's.\n"
            "                pp.argv0 = cmd\n"
            "                self.exec_command(pp, cmdclass, *parsed_arguments[1:])\n"
        ),
        "sudo.py child argv0",
    )

    write_python(path, source)


def patch_ls_py() -> None:
    path = COWRIE_SRC / "commands" / "ls.py"
    source = read_text(path)

    source = replace_once(
        source,
        (
            "            else:\n"
            "                file = self.protocol.fs.getfile(path)[:]\n"
            "                file[fs.A_NAME] = name\n"
            "                files = [file]\n"
        ),
        (
            "            else:\n"
            "                # Keep symlinks visible instead of showing the target's\n"
            "                # metadata as if it were the link itself.\n"
            "                file = self.protocol.fs.getfile(path, follow_symlinks=False)[:]\n"
            "                if path in (\"/proc/self/exe\", \"/proc/thread-self/exe\"):\n"
            "                    current = getattr(self.protocol.fs, \"current_exe\", None)\n"
            "                    if current:\n"
            "                        file[fs.A_TARGET] = current\n"
            "                file[fs.A_NAME] = name\n"
            "                files = [file]\n"
        ),
        "ls.py symlink metadata",
    )

    write_python(path, source)


def patch_cat_py() -> None:
    path = COWRIE_SRC / "commands" / "cat.py"
    source = read_text(path)

    source = replace_once(
        source,
        (
            "        if inb is None:\n"
            "            return\n"
            "\n"
            "        lines = inb.split(b\"\\n\")\n"
        ),
        (
            "        if inb is None:\n"
            "            return\n"
            "\n"
            "        # GNU cat is byte-exact.  The old line-oriented path appended a\n"
            "        # newline, so `cat /proc/self/exe | wc -c` was one byte larger\n"
            "        # than the served ELF and binary files were visibly altered.\n"
            "        if not self.number:\n"
            "            self.writeBytes(inb)\n"
            "            return\n"
            "\n"
            "        lines = inb.split(b\"\\n\")\n"
        ),
        "cat.py exact bytes",
    )

    source = replace_once(
        source,
        '        self.output(line.encode("utf-8"))\n',
        '        self.output(line.encode("utf-8") + b"\\n")\n',
        "cat.py interactive newline",
    )

    write_python(path, source)


def patch_wc_py() -> None:
    path = COWRIE_SRC / "commands" / "wc.py"
    source = read_text(path)

    source = replace_once(
        source,
        '            files = self.check_arguments("wc", args[1:])\n',
        '            files = self.check_arguments("wc", args)\n',
        "wc.py file arguments",
    )

    write_python(path, source)


def check_real_files() -> None:
    for rel in REAL_FILES:
        path = HONEYFS / rel
        if not path.is_file() or path.is_symlink():
            fail(f"honeyfs/{rel} is missing or not a regular file")
        if path.stat().st_size < 1024:
            fail(f"honeyfs/{rel} is suspiciously small")


def main() -> None:
    check_real_files()
    patch_fs_pickle()
    patch_fs_py()
    patch_protocol_py()
    patch_command_py()
    patch_busybox_py()
    patch_sudo_py()
    patch_ls_py()
    patch_cat_py()
    patch_wc_py()
    print("cowrie patch: applied real executables and /proc/self coherence")


if __name__ == "__main__":
    main()
