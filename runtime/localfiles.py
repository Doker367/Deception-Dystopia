"""Restrictive local provisioning. Parent directories are verified, not assumed.

Every database, spool, queue and private file lives under a parent directory
owned by root or the service account and not writable by group/other.  The
checks below fail closed before a leaf is created or opened, so a laxly
restored or shared parent cannot substitute the file.  Publish new files only
after complete write+fsync, using exclusive link creation.  This is POSIX-only,
matching the supported platform. No overwrite fallback.
"""
import os
from pathlib import Path
import stat
import secrets


def _trusted_owner(info, expected_uid):
    """Root or the running service, unless the caller names an exact uid."""
    if expected_uid is not None:
        return info.st_uid == expected_uid
    return info.st_uid in {0, os.geteuid()}


def open_trusted_directory(path, *, expected_uid=None, allow_sticky=False):
    """Open ``path`` with O_NOFOLLOW and require a trusted private directory.

    Trust means: real directory (never a symlink), owned by root or the service
    UID, and not writable by group/other.  ``allow_sticky`` admits shared
    sticky parents (for example ``/tmp``) while walking an ancestor chain; the
    immediate parent of a private file always uses the strict form.
    """
    path = Path(path)
    leaf = os.lstat(path)
    if stat.S_ISLNK(leaf.st_mode):
        raise PermissionError(f"private parent must not be a symlink: {path}")
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode):
            raise PermissionError(f"private parent must be a directory: {path}")
        if not _trusted_owner(info, expected_uid):
            raise PermissionError(
                f"private parent must be owned by root or the service uid: {path}")
        writable = info.st_mode & 0o022
        if writable and not (allow_sticky and info.st_mode & stat.S_ISVTX):
            raise PermissionError(
                f"private parent must not be writable by group/other: {path}")
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_private_parent(path, *, expected_uid=None):
    """Retained descriptor for the immediate parent of a private leaf."""
    return open_trusted_directory(Path(path).parent, expected_uid=expected_uid)


def verify_ancestor_chain(path):
    """Verify every existing ancestor of ``path`` is a trusted directory.

    Used by restore before creating anything: a symlinked or shared writable
    ancestor (including a ``--state-root`` supplied by the operator) must fail
    closed.  Missing ancestors are allowed because restore creates them with
    mode 0700 after the preflight.  Sticky shared roots such as ``/tmp`` are
    admitted as ancestors only; the immediate target parent stays strict.
    """
    path = Path(os.path.abspath(path))
    for candidate in path.parents:
        if not candidate.exists() and not candidate.is_symlink():
            continue
        fd = open_trusted_directory(candidate, allow_sticky=True)
        os.close(fd)


def read_private(path, max_bytes=1024*1024, expected_uid=None):
    parent = open_private_parent(path, expected_uid=expected_uid)
    os.close(parent)
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
    # Retained fd prevents leaf-parent races; the helper rejects a symlinked,
    # group/world-writable or foreign-owned parent before anything is created.
    directory = open_private_parent(path)
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
