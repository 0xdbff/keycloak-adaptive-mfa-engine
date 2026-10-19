import pytest

from src.core.config.environment import _parse_monitoring_readers


def test_empty_means_no_trusted_readers():
    assert _parse_monitoring_readers("") == frozenset()


def test_parses_issuer_and_client_pairs():
    readers = _parse_monitoring_readers(
        "https://sso.example.com/realms/master|monitoring-service, "
        "https://sso2.example.com/realms/admin/|pm"
    )
    assert readers == frozenset({
        ("https://sso.example.com/realms/master", "monitoring-service"),
        ("https://sso2.example.com/realms/admin", "pm"),
    })


@pytest.mark.parametrize("entry", [
    "https://sso.example.com/realms/master",
    "https://sso.example.com/realms/master|",
    "|monitoring-service",
])
def test_malformed_entry_raises(entry):
    with pytest.raises(ValueError, match="MONITORING_TRUSTED_READERS"):
        _parse_monitoring_readers(entry)
