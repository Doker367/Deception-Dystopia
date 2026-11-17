"""Contrato del lector de transcripciones TTY de Cowrie."""

import struct

from app.services.deception import ttylog_svc


def _ttylog(path, records):
    """Escribe un ttylog mínimo con el formato de Cowrie."""
    header = struct.pack("<I", 1) + b"\0" * 12 + struct.pack("<II", 1, 0)
    body = bytearray(header)
    for direction, text in records:
        data = text.encode()
        body += struct.pack("<IIIIII", 3, 0, len(data), direction, 1, 0)
        body += data
    path.write_bytes(bytes(body))


def test_command_outputs_pairs_commands_with_decoy_responses(tmp_path, monkeypatch):
    name = "b963d46bbd78c797ad0fd42ab284cd10f671e1ead841654126da55a490a1b705"
    _ttylog(tmp_path / name, [
        (2, "root@srv-files-01:~# "),
        (1, "id\r\n"),                    # entrada del cliente: se ignora
        (2, "root@srv-files-01:~# id\r\n"),
        (2, "uid=0(root) gid=0(root)\r\n"),
        (2, "root@srv-files-01:~# "),
        (2, "root@srv-files-01:~# whoami\r\n"),
        (2, "root\r\n"),
        (2, "root@srv-files-01:~# "),
    ])
    monkeypatch.setattr(ttylog_svc, "_base_dir", lambda: tmp_path)
    ttylog_svc._transcript.cache_clear()

    outputs = ttylog_svc.command_outputs(
        f"var/lib/cowrie/tty/{name}", ["id", "whoami", "missing"],
    )
    assert outputs == ["uid=0(root) gid=0(root)", "root", ""]


def test_symlink_outside_the_tty_directory_is_rejected(tmp_path, monkeypatch):
    tty_dir = tmp_path / "tty"
    tty_dir.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("no debe leerse", encoding="utf-8")
    name = "a" * 64
    (tty_dir / name).symlink_to(outside)
    monkeypatch.setattr(ttylog_svc, "_base_dir", lambda: tty_dir)
    assert ttylog_svc.resolve(name) is None
    assert ttylog_svc.command_outputs(name, ["id"]) == [""]


def test_path_traversal_is_not_treated_as_a_tty_reference(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.write_text("no debe leerse", encoding="utf-8")
    monkeypatch.setattr(ttylog_svc, "_base_dir", lambda: tmp_path)
    assert ttylog_svc.reference(str(outside)) == ""
    assert ttylog_svc.resolve(str(outside)) is None
