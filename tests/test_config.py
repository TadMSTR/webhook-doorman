"""Config validation, with emphasis on the `none` guard.

The guard is the part most likely to rot: it is three conditions that must all hold, it protects
against something that cannot be observed in a passing deploy, and its predecessor was a check
that could not fail. Each condition gets its own test asserting the *startup* refuses.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal, get_args, get_origin

import pytest
from pydantic import BaseModel

from webhook_doorman.config import (
    Config,
    SinkSpec,
    VerifySpec,
    load_config,
    secret_env_names,
    sink_secret_env_names,
)
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


# --------------------------------------------------------------------------------------
# Credential discovery
# --------------------------------------------------------------------------------------

# Fields whose validator constrains the value beyond its type, so a generic sample would be
# rejected. Keep this as small as it can be — every entry is a place the synthesiser is blind.
_FIELD_OVERRIDES: dict[str, Any] = {
    "allow_from": ["127.0.0.1/32"],
    "project_id": 1,
}


def _union_members(spec: Any) -> tuple[type[BaseModel], ...]:
    """The concrete models behind a discriminated `Annotated[A | B, Field(...)]` union."""
    if get_origin(spec) is Annotated:
        spec = get_args(spec)[0]
    return get_args(spec)


def _sample_value(field_name: str, annotation: Any) -> Any:
    if field_name in _FIELD_OVERRIDES:
        return _FIELD_OVERRIDES[field_name]
    if get_origin(annotation) is Literal:
        return get_args(annotation)[0]
    if field_name.endswith("_env"):
        return f"PROBE_{field_name.upper()}"
    if annotation is int:
        return 1
    return "probe"


def _minimal_instance(model: type[BaseModel]) -> BaseModel:
    """Build the smallest valid instance of `model`, with every `*_env` field populated.

    Optional `*_env` fields are set too, not just required ones: an optional credential that
    goes undiscovered fails exactly as openly as a required one, and `url_env` on
    `_EndpointMixin` is optional but is the field Plan 2's Discord and Slack sinks depend on.
    """
    values = {
        name: _sample_value(name, field.annotation)
        for name, field in model.model_fields.items()
        if field.is_required() or name.endswith("_env")
    }
    return model(**values)


def _env_field_values(instance: BaseModel) -> set[str]:
    return {
        value
        for name in type(instance).model_fields
        if name.endswith("_env") and (value := getattr(instance, name, None))
    }


class TestSinkSecretDiscovery:
    """`sink_secret_env_names` must see every `*_env` field on every member of the union.

    This is a sentinel, not a regression test. Today's four sinks pass it trivially — the four
    names the old hardcoded tuple listed happen to be all there are. It exists so that the next
    sink to carry a differently-named credential (`webhook_url_env`) fails here, in CI, rather
    than in production as a sink reporting `enabled: true` with its variable unset and its value
    absent from the redaction set.
    """

    @pytest.mark.parametrize("model", _union_members(SinkSpec), ids=lambda m: m.__name__)
    def test_every_env_field_is_discovered(self, model):
        instance = _minimal_instance(model)
        expected = _env_field_values(instance)
        assert expected, f"{model.__name__} has no *_env field — the probe is not testing anything"
        assert set(sink_secret_env_names(instance)) == expected

    def test_discovers_a_field_name_it_has_never_seen(self):
        """The mechanism, isolated from today's union.

        `webhook_url_env` is not one of the four names the old implementation knew, and is the
        exact field Plan 2 adds for Discord and Slack.
        """

        class ScratchSink(BaseModel):
            name: str = "scratch"
            type: Literal["scratch"] = "scratch"
            webhook_url_env: str = "DISCORD_WEBHOOK_URL"
            template: str = "{{ summary }}"

        assert sink_secret_env_names(ScratchSink()) == ["DISCORD_WEBHOOK_URL"]

    def test_unset_optional_env_fields_are_omitted(self):
        """An unset optional credential is not a name — it must not reach `required_env_names`."""
        ntfy = next(m for m in _union_members(SinkSpec) if m.__name__ == "NtfySink")
        instance = ntfy(
            name="push", type="ntfy", url="https://ntfy.example.invalid", topic_env="TOPIC"
        )
        assert sink_secret_env_names(instance) == ["TOPIC"]


class TestVerifySecretDiscovery:
    """`secret_env_names` is an `isinstance` chain, so exhaustiveness is the thing at risk.

    It is correct today only because all four union members are named in it. A fifth strategy
    carrying a `*_env` field would fall through to `return []` and be invisible in precisely the
    way `sink_secret_env_names` used to be, so assert it rather than re-reading it each review.
    """

    @pytest.mark.parametrize("model", _union_members(VerifySpec), ids=lambda m: m.__name__)
    def test_every_env_field_is_discovered(self, model):
        instance = _minimal_instance(model)
        assert set(secret_env_names(instance)) == _env_field_values(instance)
