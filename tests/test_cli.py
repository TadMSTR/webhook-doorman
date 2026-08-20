"""The console entry point, up to but not including binding a port."""

from __future__ import annotations

import pytest

from webhook_doorman.__main__ import main


def test_check_validates_and_exits_zero(base_config, write_config, capsys):
    path = write_config(base_config)
    assert main(["--config", str(path), "--check"]) == 0
    assert "config OK" in capsys.readouterr().out


def test_check_reports_a_bad_config_and_exits_two(base_config, write_config, capsys):
    base_config["sources"][0]["sinks"] = ["missing-sink"]
    path = write_config(base_config)
    assert main(["--config", str(path), "--check"]) == 2
    assert "config error" in capsys.readouterr().err


def test_missing_file_exits_two(tmp_path, capsys):
    assert main(["--config", str(tmp_path / "absent.yml"), "--check"]) == 2
    assert "cannot read config file" in capsys.readouterr().err


def test_config_path_comes_from_the_environment(base_config, write_config, monkeypatch, capsys):
    path = write_config(base_config)
    monkeypatch.setenv("WEBHOOK_DOORMAN_CONFIG", str(path))
    assert main(["--check"]) == 0
    assert "config OK" in capsys.readouterr().out


def test_version_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "webhook-doorman" in capsys.readouterr().out


def test_shipped_example_config_is_valid(capsys):
    """config.example.yml is documentation people copy. A broken one is a broken quickstart."""
    from pathlib import Path

    example = Path(__file__).resolve().parents[1] / "config.example.yml"
    assert main(["--config", str(example), "--check"]) == 0
