from types import SimpleNamespace

import pytest

from attacker.scripts import dns_tunnel


def test_default_cli_preserves_session_defaults():
    args = dns_tunnel.parse_args([])

    assert args.sessions == 0
    assert args.session_duration == 2.0
    assert args.sessions_per_server == 12
    assert args.session_gap == 0.0
    assert args.retries == 3


def test_profile_applies_bounded_session_values():
    args = dns_tunnel.parse_args(["--profile", "short_sparse"])

    assert args.sessions == 300
    assert args.session_duration == 1.0
    assert args.sessions_per_server == 6
    assert args.session_gap == 0.25
    assert args.retries == 3


def test_dense_batches_uses_safe_batch_size_and_allows_override():
    args = dns_tunnel.parse_args(["--profile", "dense_batches"])
    overridden = dns_tunnel.parse_args(
        ["--profile", "dense_batches", "--sessions-per-server", "7"]
    )

    assert args.sessions_per_server == 15
    assert overridden.sessions_per_server == 7


def test_explicit_values_override_dns_profile_values():
    args = dns_tunnel.parse_args(
        [
            "--profile",
            "short_sparse",
            "--sessions",
            "2",
            "--session-duration",
            "1",
            "--sessions-per-server",
            "1",
            "--session-gap",
            "0.1",
            "--retries",
            "2",
        ]
    )

    assert args.sessions == 2
    assert args.session_duration == 1.0
    assert args.sessions_per_server == 1
    assert args.session_gap == 0.1
    assert args.retries == 2
    assert args.server == "10.10.0.2"


def test_client_command_uses_iodine_null_transport():
    args = SimpleNamespace(password="test", server="10.10.0.2", domain="tunnel.lab")

    command = dns_tunnel.build_client_command(args)

    assert command == "iodine -f -T NULL -P test 10.10.0.2 tunnel.lab"


def test_invalid_session_gap_is_rejected():
    with pytest.raises(SystemExit):
        dns_tunnel.parse_args(["--sessions", "1", "--session-gap", "-0.1"])
