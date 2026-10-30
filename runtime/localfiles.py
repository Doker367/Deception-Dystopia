"""Restrictive local provisioning. Parent directories must be trusted.

Publish new files only after complete write+fsync, using exclusive link creation.
This is POSIX-only, matching the supported platform. No overwrite fallback.
"""
import os
from pathlib import Path
import stat
import secrets


def read_private(path, max_bytes=1024*1024, expected_uid=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_mode & 0o077
                or before.st_size > max_bytes or (expected_uid is not None and before.st_uid != expected_uid)):
            raise PermissionError("expected bounded private regular file with trusted owner")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(max_bytes + 1)
        after = os.fstat(fd)
        if len(data) != before.st_size or len(data) > max_bytes or before.st_mtime_ns != after.st_mtime_ns or before.st_ctime_ns != after.st_ctime_ns:
            raise PermissionError("private file changed while reading")
        return data
    finally:
        os.close(fd)


def _publish(path, data, replace):
    path = Path(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    # Caller guarantees trusted parents; retained fd prevents leaf-parent races.
    name = ".dystopia-" + secrets.token_hex(16)
    fd = None
    created = False
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        created = True
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(name, path.name, src_dir_fd=directory, dst_dir_fd=directory)
            created = False
        else:
            try:
                os.link(name, path.name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
            except FileExistsError:
                return False
            os.unlink(name, dir_fd=directory)
            created = False
        os.fsync(directory)
        return True
    finally:
        if fd is not None:
            os.close(fd)
        if created:
            os.unlink(name, dir_fd=directory)
        os.close(directory)


def create_private(path, data):
    """Complete exclusive publish. Existing files are never reset."""
    if not _publish(path, data, replace=False):
        read_private(path)
        return False
    return True


def replace_private(path, data):
    """Explicit operator mutation, never used for installer overwrite."""
    path = Path(path)
    if path.exists() or path.is_symlink():
        read_private(path)
    _publish(path, data, replace=True)
