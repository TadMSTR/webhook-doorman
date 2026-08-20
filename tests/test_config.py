"""Config validation, with emphasis on the `none` guard.

The guard is the part most likely to rot: it is three conditions that must all hold, it protects
against something that cannot be observed in a passing deploy, and its predecessor was a check
that could not fail. Each condition gets its own test asserting the *startup* refuses.
"""

from __future__ import annotations

import pytest

from webhook_doorman.config import Config, load_config
from webhook_doorman.errors import ConfigError


def none_source(**overrides) -> dict:
    source = {
        "name": "internal",
        "path": "/webhook/internal",
        "verify": {
            "strategy": "none",
            "unverified_reason": "loopback-only producer on the host",
            "allow_from": ["127.0.0.1/32"],
        },
        "sinks": ["notes"],
    }
    source["verify"].update(overrides)
    return source


def config_with(source: dict, *, allow_unverified: bool = True) -> dict:
    return {
        "server": {"allow_unverified": allow_unverified},
        "sources": [source],
        "sinks": [{"name": "notes", "type": "http", "url": "https://x.example.invalid"}],
    }


class TestNoneGuard:
    def test_valid_none_source_loads(self):
        config = Config.model_validate(config_with(none_source()))
        assert config.sources[0].verify.strategy == "none"

    def test_refuses_without_allow_unverified(self):
        with pytest.raises(ValueError, match="allow_unverified"):
            Config.model_validate(config_with(none_source(), allow_unverified=False))

    def test_error_names_every_offending_source(self):
        data = config_with(none_source(), allow_unverified=False)
        second = none_source()
        second["name"] = "other"
        second["path"] = "/webhook/other"
        data["sources"].append(second)
        with pytest.raises(ValueError) as exc:
            Config.model_validate(data)
        assert "'internal'" in str(exc.value)
        assert "'other'" in str(exc.value)

    def test_refuses_blank_unverified_reason(self):
        with pytest.raises(ValueError, match="reason"):
            Config.model_validate(config_with(none_source(unverified_reason="   ")))

    def test_refuses_missing_unverified_reason(self):
        source = none_source()
        del source["verify"]["unverified_reason"]
        with pytest.raises(ValueError):
            Config.model_validate(config_with(source))

    def test_refuses_empty_allow_from(self):
        with pytest.raises(ValueError, match="allow_from"):
            Config.model_validate(config_with(none_source(allow_from=[])))

    def test_refuses_absent_allow_from(self):
        """An omitted allow_from is an error, never an implicit allow-all."""
        source = none_source()
        del source["verify"]["allow_from"]
        with pytest.raises(ValueError):
            Config.model_validate(config_with(source))

    def test_refuses_malformed_cidr(self):
        with pytest.raises(ValueError, match="not a valid CIDR"):
            Config.model_validate(config_with(none_source(allow_from=["10.0.0.0/48"])))


class TestStructuralValidation:
    def test_unknown_sink_reference_is_rejected(self, base_config):
        base_config["sources"][0]["sinks"] = ["nope"]
        with pytest.raises(ValueError, match="unknown sink"):
            Config.model_validate(base_config)

    def test_duplicate_source_name_is_rejected(self, base_config):
        clone = dict(base_config["sources"][0])
        clone["path"] = "/webhook/other"
        base_config["sources"].append(clone)
        with pytest.raises(ValueError, match="duplicate source name"):
            Config.model_validate(base_config)

    def test_duplicate_path_is_rejected(self, base_config):
        clone = dict(base_config["sources"][0])
        clone["name"] = "github2"
        base_config["sources"].append(clone)
        with pytest.raises(ValueError, match="duplicate source path"):
            Config.model_validate(base_config)

    def test_no_sources_is_rejected(self, base_config):
        base_config["sources"] = []
        with pytest.raises(ValueError, match="at least one source"):
            Config.model_validate(base_config)

    def test_source_without_sinks_is_rejected(self, base_config):
        base_config["sources"][0]["sinks"] = []
        with pytest.raises(ValueError, match="at least one sink"):
            Config.model_validate(base_config)

    def test_unknown_key_is_rejected(self, base_config):
        """A typo'd key must not be silently ignored — that is how a verify setting goes missing."""
        base_config["sources"][0]["verifyy"] = {}
        with pytest.raises(ValueError):
            Config.model_validate(base_config)

    def test_path_must_start_with_slash(self, base_config):
        base_config["sources"][0]["path"] = "webhook/github"
        with pytest.raises(ValueError, match="must start with"):
            Config.model_validate(base_config)

    def test_source_may_not_shadow_admin_prefix(self, base_config):
        base_config["sources"][0]["path"] = "/admin/replay/1"
        with pytest.raises(ValueError, match="/admin"):
            Config.model_validate(base_config)

    def test_dedup_may_not_key_on_the_verify_header(self, base_config):
        """Redaction would collapse every event onto one dedup id and discard the rest."""
        base_config["sources"][0]["dedup"] = {"id_header": "X-Hub-Signature-256"}
        with pytest.raises(ValueError, match="credential header"):
            Config.model_validate(base_config)

    def test_dedup_may_not_key_on_authorization(self, base_config):
        base_config["sources"][0]["dedup"] = {"id_header": "Authorization"}
        with pytest.raises(ValueError, match="credential header"):
            Config.model_validate(base_config)

    def test_dedup_header_check_is_case_insensitive(self, base_config):
        base_config["sources"][0]["dedup"] = {"id_header": "authorization"}
        with pytest.raises(ValueError, match="credential header"):
            Config.model_validate(base_config)

    def test_an_ordinary_delivery_header_is_fine(self, base_config):
        base_config["sources"][0]["dedup"] = {"id_header": "X-GitHub-Delivery"}
        assert Config.model_validate(base_config).sources[0].dedup.id_header

    def test_sink_requires_exactly_one_url_form(self, base_config):
        base_config["sinks"][0]["url_env"] = "SINK_URL"
        with pytest.raises(ValueError, match="exactly one"):
            Config.model_validate(base_config)

    def test_sink_requires_at_least_one_url_form(self, base_config):
        del base_config["sinks"][0]["url"]
        with pytest.raises(ValueError, match="exactly one"):
            Config.model_validate(base_config)


class TestLoadConfig:
    def test_loads_a_file(self, base_config, write_config):
        config = load_config(write_config(base_config))
        assert {s.name for s in config.sources} == {"github", "internal"}

    def test_missing_file_names_the_path(self, tmp_path):
        with pytest.raises(ConfigError, match="cannot read config file"):
            load_config(tmp_path / "absent.yml")

    def test_invalid_yaml_names_the_file(self, tmp_path):
        path = tmp_path / "config.yml"
        path.write_text("sources: [\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="not valid YAML"):
            load_config(path)

    def test_empty_file_is_rejected(self, tmp_path):
        path = tmp_path / "config.yml"
        path.write_text("", encoding="utf-8")
        with pytest.raises(ConfigError, match="is empty"):
            load_config(path)

    def test_non_mapping_is_rejected(self, tmp_path):
        path = tmp_path / "config.yml"
        path.write_text("- a\n- b\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="must contain a mapping"):
            load_config(path)

    def test_error_message_names_the_field(self, base_config, write_config):
        base_config["sources"][0]["verify"]["secret_env"] = ""
        with pytest.raises(ConfigError) as exc:
            load_config(write_config(base_config))
        message = str(exc.value)
        assert "secret_env" in message
        assert "config.yml" in message

    def test_required_env_names_collects_every_reference(self, base_config):
        base_config["admin"] = {"token_env": "ADMIN_TOKEN"}
        config = Config.model_validate(base_config)
        assert config.required_env_names() == {
            "GITHUB_WEBHOOK_SECRET",
            "INTERNAL_TOKEN",
            "ADMIN_TOKEN",
        }
