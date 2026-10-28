"""The incident registry must be derivable, complete and self-consistent.

Adding an incident type used to mean editing a class, the registry tuple, the key
prefix map in `constants` and the module `__all__`. Forgetting the prefix map
failed only when the first event of that type arrived, as a `KeyError` on the
alert path. These tests pin the invariant: one declarative table, and every
derived structure agrees with it.
"""

from __future__ import annotations

from opencanary_correlator.constants import INCIDENT_KEY_PREFIX
from opencanary_correlator.core.incident_model import INCIDENT_TYPES
from opencanary_correlator.incident_specs import INCIDENT_SPECS


def test_specs_registry_and_key_prefixes_cover_the_same_incidents() -> None:
    names = {spec.name for spec in INCIDENT_SPECS}

    assert len(names) == len(INCIDENT_SPECS), "a spec is declared twice"
    assert set(INCIDENT_TYPES) == names
    assert set(INCIDENT_KEY_PREFIX) == names


def test_every_spec_describes_its_registered_class() -> None:
    for spec in INCIDENT_SPECS:
        incident_cls = INCIDENT_TYPES[spec.name]
        assert incident_cls.INCIDENT_NAME == spec.name
        assert incident_cls.DESCRIPTION == spec.description
        assert incident_cls.__name__ == spec.class_name
        assert INCIDENT_KEY_PREFIX[spec.name] == spec.key_prefix


def test_key_prefixes_are_unique_and_namespaced() -> None:
    prefixes = [spec.key_prefix for spec in INCIDENT_SPECS]

    assert len(set(prefixes)) == len(prefixes), "two incidents share a key prefix"
    for prefix in prefixes:
        assert prefix.startswith("incident:")
        assert prefix.endswith(":")
