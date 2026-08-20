"""Secret resolution and the disable-rather-than-crash policy.

The choice being tested: a missing variable disables one source, it does not take the router
down and it does not enable the source unverified. Both of the other two options are available
and both are wrong.
"""

from __future__ import annotations

from webhook_doorman.config import Config
from webhook_doorman.secrets import resolve


def test_all_sources_enabled_when_env_is_complete(base_config, base_env):
    resolved = resolve(Config.model_validate(base_config), base_env)
    assert all(state.enabled for state in resolved.sources.values())


def test_missing_variable_disables_only_that_source(base_config, base_env):
    del base_env["GITHUB_WEBHOOK_SECRET"]
    resolved = resolve(Config.model_validate(base_config), base_env)
    assert resolved.sources["github"].enabled is False
    assert resolved.sources["internal"].enabled is True


def test_disabled_reason_names_the_variable(base_config, base_env):
    del base_env["GITHUB_WEBHOOK_SECRET"]
    resolved = resolve(Config.model_validate(base_config), base_env)
    state = resolved.sources["github"]
    assert "GITHUB_WEBHOOK_SECRET" in state.disabled_reason
    assert state.missing_env == ("GITHUB_WEBHOOK_SECRET",)


def test_whitespace_only_value_counts_as_missing(base_config, base_env):
    base_env["GITHUB_WEBHOOK_SECRET"] = "\t \n"
    resolved = resolve(Config.model_validate(base_config), base_env)
    assert resolved.sources["github"].enabled is False


def test_explicitly_disabled_source_reports_that_reason(base_config, base_env):
    base_config["sources"][0]["enabled"] = False
    resolved = resolve(Config.model_validate(base_config), base_env)
    assert resolved.sources["github"].disabled_reason == "disabled in config"


def test_sink_missing_its_token_is_disabled(base_config, base_env):
    base_config["sinks"][0] = {
        "name": "notes",
        "type": "matrix",
        "url": "https://matrix.example.invalid",
        "token_env": "MATRIX_TOKEN",
        "room_env": "MATRIX_ROOM",
    }
    resolved = resolve(Config.model_validate(base_config), base_env)
    assert resolved.sinks["notes"].enabled is False
    assert set(resolved.sinks["notes"].missing_env) == {"MATRIX_TOKEN", "MATRIX_ROOM"}


def test_secret_values_collects_only_non_empty(base_config, base_env):
    base_env["INTERNAL_TOKEN"] = ""
    resolved = resolve(Config.model_validate(base_config), base_env)
    assert base_env["GITHUB_WEBHOOK_SECRET"] in resolved.secret_values
    assert "" not in resolved.secret_values


def test_unverified_source_names_lists_only_enabled_none_sources():
    data = {
        "server": {"allow_unverified": True},
        "sources": [
            {
                "name": "internal",
                "path": "/webhook/internal",
                "verify": {
                    "strategy": "none",
                    "unverified_reason": "loopback producer",
                    "allow_from": ["127.0.0.1/32"],
                },
                "sinks": ["notes"],
            },
            {
                "name": "off",
                "path": "/webhook/off",
                "enabled": False,
                "verify": {
                    "strategy": "none",
                    "unverified_reason": "loopback producer",
                    "allow_from": ["127.0.0.1/32"],
                },
                "sinks": ["notes"],
            },
        ],
        "sinks": [{"name": "notes", "type": "http", "url": "https://x.example.invalid"}],
    }
    resolved = resolve(Config.model_validate(data), {})
    assert resolved.unverified_source_names() == ["internal"]


class TestAdminToken:
    @staticmethod
    def config_with_admin(base_config, **admin) -> Config:
        base_config["admin"] = {"token_env": "ADMIN_TOKEN", **admin}
        return Config.model_validate(base_config)

    def test_disabled_when_no_token_env_configured(self, base_config, base_env):
        assert resolve(Config.model_validate(base_config), base_env).admin_token() is None

    def test_disabled_when_variable_is_unset(self, base_config, base_env):
        config = self.config_with_admin(base_config)
        assert resolve(config, base_env).admin_token() is None

    def test_short_token_is_treated_as_absent(self, base_config, base_env):
        """A 6-character token on an endpoint that re-fires real events is worse than none."""
        config = self.config_with_admin(base_config)
        base_env["ADMIN_TOKEN"] = "short1"
        assert resolve(config, base_env).admin_token() is None

    def test_long_enough_token_enables_replay(self, base_config, base_env):
        config = self.config_with_admin(base_config)
        base_env["ADMIN_TOKEN"] = "a" * 32
        assert resolve(config, base_env).admin_token() == "a" * 32

    def test_min_length_is_configurable(self, base_config, base_env):
        config = self.config_with_admin(base_config, min_token_length=8)
        base_env["ADMIN_TOKEN"] = "a" * 8
        assert resolve(config, base_env).admin_token() == "a" * 8
