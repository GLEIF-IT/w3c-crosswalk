"""Contract tests for the local long-running operation store."""

from __future__ import annotations

from vc_isomer.longrunning import OperationMonitor


def test_operation_monitor_tracks_pending_completed_failed_and_deleted(tmp_path):
    """Persist the full lifecycle of a verifier operation in LMDB."""
    monitor = OperationMonitor(head_dir_path=str(tmp_path), name="ops")
    try:
        pending = monitor.submit(typ="verify-vc", request={"token": "abc"})
        assert pending.done is False
        assert pending.metadata["state"] == "pending"
        assert "submittedAt" in pending.metadata
        assert "updatedAt" in pending.metadata

        monitor.mark_running(pending.name)
        running = monitor.get(pending.name)
        assert running.done is False
        assert running.metadata["state"] == "running"

        monitor.complete(pending.name, {"ok": True, "kind": "vc+jwt"})
        completed = monitor.get(pending.name)
        assert completed.done is True
        assert completed.response["ok"] is True

        failed = monitor.submit(typ="verify-vc", request={"token": "bad"})
        monitor.fail(failed.name, code=400, message="invalid vc+jwt", details={"errors": ["bad token"]})
        failed_terminal = monitor.get(failed.name)
        assert failed_terminal.done is True
        assert failed_terminal.error.code == 400

        assert monitor.rem(completed.name) is True
        assert monitor.get(completed.name) is None
    finally:
        monitor.close()


def test_operation_monitor_lists_and_filters_by_type(tmp_path):
    """List operation documents and support type filtering."""
    monitor = OperationMonitor(head_dir_path=str(tmp_path), name="ops-filter")
    try:
        monitor.submit(typ="verify-vc", request={"token": "vc"})
        monitor.submit(typ="verify-vp", request={"token": "vp"})

        all_ops = monitor.get_ops()
        vc_ops = monitor.get_ops(type="verify-vc")

        assert len(all_ops) == 2
        assert len(vc_ops) == 1
        assert vc_ops[0].name.startswith("verify-vc.")
    finally:
        monitor.close()
