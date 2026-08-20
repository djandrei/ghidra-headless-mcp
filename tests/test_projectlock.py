"""Cross-process project locking.

The in-process threading lock cannot stop a *second* server process. That
happened for real: during a 123-binary Flare-On run, one 23-minute analysis led
to a second stdio server being spawned, the two raced for Ghidra's project lock,
and 33 consecutive imports failed with LockException.
"""

import multiprocessing as mp
import time

import pytest

from ghmcp import config, headless
from ghmcp.errors import GhidraError, HeadlessTimeout


def _hold(loc, name, seconds, started):
    config.PROJECT_LOCATION = loc
    config.PROJECT_NAME = name
    with headless.project_lock():
        started.set()
        time.sleep(seconds)


class TestProjectLock:
    def test_lock_file_lives_beside_the_project(self, project):
        with headless.project_lock():
            hits = list(project.glob(".*.ghmcp.lock"))
        assert hits, "expected a lock file next to the project"

    def test_it_is_reentrant_across_sequential_calls(self, project):
        for _ in range(3):
            with headless.project_lock():
                pass  # must not deadlock or leak the handle

    def test_a_second_process_is_excluded(self, project):
        """The property the threading lock could not provide."""
        ctx = mp.get_context("fork")
        started = ctx.Event()
        p = ctx.Process(target=_hold, args=(project, config.PROJECT_NAME, 3, started))
        p.start()
        try:
            assert started.wait(10), "helper never acquired the lock"
            t0 = time.monotonic()
            with headless.project_lock(timeout=30):
                waited = time.monotonic() - t0
            assert waited > 1.0, f"acquired in {waited:.2f}s — exclusion did not hold"
        finally:
            p.join(15)

    def test_waiting_past_the_deadline_raises_rather_than_hanging(self, project):
        ctx = mp.get_context("fork")
        started = ctx.Event()
        p = ctx.Process(target=_hold, args=(project, config.PROJECT_NAME, 8, started))
        p.start()
        try:
            assert started.wait(10)
            with pytest.raises(HeadlessTimeout, match="orphaned"):
                with headless.project_lock(timeout=2):
                    pass
        finally:
            p.join(15)

    def test_the_lock_is_released_when_the_body_raises(self, project):
        with pytest.raises(ValueError):
            with headless.project_lock():
                raise ValueError("boom")
        with headless.project_lock(timeout=3):
            pass  # would block if the failed body had leaked the lock


class TestGhidraLockErrorIsExplained:
    def test_a_ghidra_lock_exception_gets_its_own_message(self, project, monkeypatch):
        class Proc:
            returncode = 1
            stdout = ("INFO  Opening project...\n"
                      "ERROR Abort due to Headless analyzer error: "
                      "ghidra.framework.store.LockException: Unable to lock project!\n")
            stderr = ""

        monkeypatch.setattr(headless.subprocess, "run", lambda *a, **k: Proc())
        with pytest.raises(GhidraError, match="could not lock the project"):
            headless.run_headless(["-import", "x"], timeout=10)

    def test_other_failures_still_report_the_log(self, project, monkeypatch):
        class Proc:
            returncode = 1
            stdout = "ERROR something else entirely\n"
            stderr = ""

        monkeypatch.setattr(headless.subprocess, "run", lambda *a, **k: Proc())
        from ghmcp.errors import ExportFailure

        with pytest.raises(ExportFailure, match="something else entirely"):
            headless.run_headless(["-import", "x"], timeout=10)
