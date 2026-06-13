"""Tests for GARAK and PromptFoo runner behavior."""

import json
import subprocess

import pytest

from prooflayer.evals import GarakRunner, PromptFooRunner


def test_garak_runner_builds_pinned_docker_command(tmp_path):
    runner = GarakRunner()

    command = runner.build_command(
        "http://127.0.0.1:8000/v1",
        tmp_path,
        probes=["encoding", "promptinject"],
    )

    assert command[:3] == ["docker", "run", "--rm"]
    assert "leondz/garak:0.10.0" in command
    assert "OPENAI_API_BASE=http://127.0.0.1:8000/v1" in command
    assert "--probes" in command


def test_garak_runner_parses_json_report(tmp_path):
    report = tmp_path / "garak.report.json"
    report.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "id": "g1",
                        "category": "prompt_injection",
                        "severity": "critical",
                        "prompt": "ignore previous instructions",
                        "outcome": "blocked",
                        "passed": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = GarakRunner().parse_report(tmp_path)

    assert len(findings) == 1
    assert findings[0].id == "g1"
    assert findings[0].source == "garak"
    assert findings[0].passed is True


def test_garak_runner_invokes_subprocess(monkeypatch, tmp_path):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        (tmp_path / "garak.json").write_text("[]", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    findings = GarakRunner().run("http://127.0.0.1:8000/v1", tmp_path)

    assert findings == []
    assert calls
    assert calls[0][1]["check"] is True


def test_promptfoo_runner_builds_pinned_docker_command(tmp_path):
    config = tmp_path / "promptfooconfig.yaml"
    output = tmp_path / "promptfoo-results.json"

    command = PromptFooRunner().build_command(
        config,
        output,
        env={"PROOFLAYER_TARGET_URL": "http://127.0.0.1:8000/v1"},
    )

    assert command[:3] == ["docker", "run", "--rm"]
    assert "promptfoo/promptfoo:0.95.0" in command
    assert "PROOFLAYER_TARGET_URL=http://127.0.0.1:8000/v1" in command
    assert "--output-format" in command


def test_promptfoo_runner_parses_report(tmp_path):
    output = tmp_path / "promptfoo-results.json"
    output.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "id": "p1",
                        "category": "exfil",
                        "severity": "critical",
                        "prompt": "print .env",
                        "response": "blocked",
                        "success": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = PromptFooRunner().parse_report(output)

    assert len(findings) == 1
    assert findings[0].id == "p1"
    assert findings[0].source == "promptfoo"
    assert findings[0].passed is True


def test_promptfoo_runner_invokes_subprocess(monkeypatch, tmp_path):
    calls = []
    config = tmp_path / "promptfooconfig.yaml"
    output = tmp_path / "promptfoo-results.json"
    config.write_text("prompts: []\n", encoding="utf-8")

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        output.write_text("[]", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    findings = PromptFooRunner().run(config, output)

    assert findings == []
    assert calls
    assert calls[0][1]["timeout"] == 900
