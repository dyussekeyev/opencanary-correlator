"""Configuration checks for the opt-in MISP publisher."""

from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError

from opencanary_correlator.app.describe import describe_settings, log_secrets


def test_misp_is_off_by_default(settings_factory: object) -> None:
    settings = settings_factory()  # type: ignore[operator]
    assert settings.misp_enabled is False
    assert settings.misp_url is None
    assert settings.misp_api_key is None


def test_enabling_misp_requires_url_and_key(settings_factory: object) -> None:
    with pytest.raises(ValidationError, match="OCC_MISP_URL"):
        settings_factory(misp_enabled=True)  # type: ignore[operator]
    with pytest.raises(ValidationError, match="OCC_MISP_API_KEY"):
        settings_factory(  # type: ignore[operator]
            misp_enabled=True, misp_url="https://misp.test"
        )


def test_misp_url_must_be_https_without_query_or_fragment(settings_factory: object) -> None:
    with pytest.raises(ValidationError, match="https"):
        settings_factory(misp_url="http://misp.test")  # type: ignore[operator]
    with pytest.raises(ValidationError, match="query"):
        settings_factory(misp_url="https://misp.test/?key=secret")  # type: ignore[operator]
    settings = settings_factory(misp_url="http://127.0.0.1:8080/misp/")  # type: ignore[operator]
    assert settings.misp_url == "http://127.0.0.1:8080/misp"


def test_sharing_group_requires_distribution_four(settings_factory: object) -> None:
    with pytest.raises(ValidationError, match="OCC_MISP_SHARING_GROUP_ID"):
        settings_factory(misp_distribution=4)  # type: ignore[operator]
    with pytest.raises(ValidationError, match="requires OCC_MISP_DISTRIBUTION=4"):
        settings_factory(  # type: ignore[operator]
            misp_distribution=1, misp_sharing_group_id=7
        )
    settings = settings_factory(  # type: ignore[operator]
        misp_distribution=4, misp_sharing_group_id=7
    )
    assert settings.misp_distribution == 4


def test_misp_tlp_and_tags_are_validated(settings_factory: object) -> None:
    with pytest.raises(ValidationError, match="misp_tlp"):
        settings_factory(misp_tlp="purple")  # type: ignore[operator]
    with pytest.raises(ValidationError, match="control"):
        settings_factory(misp_tags=["bad\x00tag"])  # type: ignore[operator]
    settings = settings_factory(misp_tags=["honeypot", "honeypot", "custom"])  # type: ignore[operator]
    assert settings.misp_tags == ["honeypot", "custom"]


def test_misp_to_ids_types_only_accept_known_incidents(settings_factory: object) -> None:
    with pytest.raises(ValidationError, match="unknown misp_to_ids_types"):
        settings_factory(misp_to_ids_types=["ssh.login_attempt", "not.real"])  # type: ignore[operator]


def test_check_config_describes_misp_without_the_api_key(settings_factory: object) -> None:
    settings = settings_factory(  # type: ignore[operator]
        misp_enabled=True,
        misp_url="https://misp.test",
        misp_api_key=SecretStr("very-secret"),
    )
    described = describe_settings(settings)
    assert described["misp"]["enabled"] is True
    assert described["misp"]["api_key_configured"] is True
    assert described["misp"]["publish_mode"] == "draft"
    assert "very-secret" not in repr(described)
    assert "very-secret" in log_secrets(settings)


def test_misp_key_is_hidden_from_settings_repr(settings_factory: object) -> None:
    settings = settings_factory(misp_api_key=SecretStr("very-secret"))  # type: ignore[operator]
    assert "very-secret" not in repr(settings)
