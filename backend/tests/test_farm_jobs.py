"""Кап детальных списков в job.result."""

from app.farm.jobs import _cap_result


def test_cap_result_truncates_lists_keeps_counters() -> None:
    payload = {
        "hosts_created": 300,
        "ports_created": 900,
        "hosts": list(range(300)),
        "errors": list(range(250)),
    }
    capped = _cap_result(payload, 200)

    assert capped["hosts_created"] == 300  # счётчики нетронуты
    assert capped["ports_created"] == 900
    assert len(capped["hosts"]) == 200  # список обрезан
    assert len(capped["errors"]) == 200


def test_cap_result_leaves_short_lists() -> None:
    payload = {"ips": [1, 2, 3], "files": [], "errors": ["x"]}
    capped = _cap_result(payload, 200)

    assert capped["ips"] == [1, 2, 3]
    assert capped["files"] == []
    assert capped["errors"] == ["x"]
