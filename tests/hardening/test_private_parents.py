"""RT-06: fail-closed trust checks for parents of private runtime files.

Every test builds its fixtures under pytest's temporary directory (mode 0700),
so the suite does not depend on host provisioning.  A deliberately lax parent
must be rejected before a database or private file is created.
"""
import os
import stat

import pytest

from runtime.localfiles import (
    create_private,
    open_private_parent,
    read_private,
    replace_private,
    verify_ancestor_chain,
)
from runtime.storage import EventStore, database


@pytest.mark.parametrize("mode", [0o777, 0o770, 0o772, 0o776])
def test_database_rejects_group_or_world_writable_parent(tmp_path, mode):
    parent = tmp_path / "shared"
    parent.mkdir()
    parent.chmod(mode)
    try:
        with pytest.raises(PermissionError):
            with database(parent / "events.db", max_bytes=8 * 1024 * 1024):
                pass
        assert not (parent / "events.db").exists()
    finally:
        parent.chmod(0o700)


def test_database_accepts_a_private_service_parent(tmp_path):
    parent = tmp_path / "state" / "ingest"
    parent.mkdir(parents=True, mode=0o700)
    parent.chmod(0o700)
    with database(parent / "events.db", max_bytes=8 * 1024 * 1024) as db:
        db.execute("CREATE TABLE probe(value TEXT)")
    assert stat.S_IMODE((parent / "events.db").stat().st_mode) == 0o600
    # EventStore and Registry share the same primitive and must still work.
    store = EventStore(parent / "store.db", max_bytes=8 * 1024 * 1024)
    assert store.health()["events"] == 0


def test_database_rejects_a_symlinked_parent(tmp_path):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(PermissionError):
        with database(link / "events.db", max_bytes=8 * 1024 * 1024):
            pass
    assert not (real / "events.db").exists()


def test_private_files_refuse_an_insecure_parent(tmp_path):
    parent = tmp_path / "lax"
    parent.mkdir()
    parent.chmod(0o777)
    try:
        with pytest.raises(PermissionError):
            create_private(parent / "token", b"synthetic")
        assert not (parent / "token").exists()

        leaked = parent / "already-token"
        leaked.write_bytes(b"synthetic")
        leaked.chmod(0o600)
        with pytest.raises(PermissionError):
            read_private(leaked)
        with pytest.raises(PermissionError):
            replace_private(leaked, b"replacement")
        assert leaked.read_bytes() == b"synthetic"
    finally:
        parent.chmod(0o700)


def test_expected_service_uid_is_enforced(tmp_path):
    parent = tmp_path / "state"
    parent.mkdir(mode=0o700)
    with pytest.raises(PermissionError):
        open_private_parent(parent / "token", expected_uid=os.geteuid() + 1)


def test_ancestor_chain_rejects_a_symlinked_component(tmp_path):
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link = tmp_path / "ancestor"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(PermissionError):
        verify_ancestor_chain(link / "child" / "leaf")


def test_ancestor_chain_accepts_the_private_tmp_tree(tmp_path):
    # pytest's tree is 0700 and includes only trusted ancestors; this is the
    # same shape as /var/lib/dystopia and must remain usable offline.
    verify_ancestor_chain(tmp_path / "state" / "ingest" / "events.db")
