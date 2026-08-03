"""Реклейм застрявших задач рекон-фермы."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.worker.recon_worker import reclaim_stale_jobs


def _db_returning(jobs: list) -> MagicMock:
    db = MagicMock()
    result = MagicMock()
    result.all = MagicMock(return_value=jobs)
    db.scalars = AsyncMock(return_value=result)
    db.commit = AsyncMock()
    return db


@pytest.mark.asyncio
async def test_reclaim_resets_stale_to_pending() -> None:
    running = SimpleNamespace(id=1, kind="hosts", status="running", attempts=1)
    queued = SimpleNamespace(id=2, kind="ips", status="queued", attempts=0)
    db = _db_returning([running, queued])

    n = await reclaim_stale_jobs(db, older_than_seconds=1800, max_attempts=3)

    assert n == 2
    assert running.status == "pending"
    assert queued.status == "pending"
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_reclaim_no_commit_when_nothing_stale() -> None:
    db = _db_returning([])

    n = await reclaim_stale_jobs(db, older_than_seconds=1800, max_attempts=3)

    assert n == 0
    db.commit.assert_not_awaited()
