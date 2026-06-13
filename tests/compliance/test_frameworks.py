"""Tests for packaged compliance framework registries."""

from importlib import resources

import yaml

import prooflayer.compliance.frameworks as frameworks


REQUIRED_CONTROL_FIELDS = {
    "id",
    "title",
    "description",
    "evidence_types",
    "audit_perspective",
    "cross_mappings",
}


def _load_frameworks():
    for path in resources.files(frameworks).glob("*.yaml"):
        yield path.name, yaml.safe_load(path.read_text(encoding="utf-8"))


def test_all_expected_framework_registries_are_packaged():
    names = {name for name, _ in _load_frameworks()}

    assert names == {
        "eu_ai_act.yaml",
        "hipaa.yaml",
        "nist_ai_rmf.yaml",
        "soc2.yaml",
    }


def test_framework_registries_have_required_schema():
    for name, payload in _load_frameworks():
        assert payload["framework"]
        assert payload["name"]
        assert payload["version"]
        assert len(payload["controls"]) >= 20, name

        control_ids = set()
        for control in payload["controls"]:
            assert REQUIRED_CONTROL_FIELDS.issubset(control), control
            assert control["id"] not in control_ids
            assert control["evidence_types"]
            assert isinstance(control["cross_mappings"], list)
            control_ids.add(control["id"])
