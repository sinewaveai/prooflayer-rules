from argparse import Namespace

from prooflayer import cli


def test_proxy_command_passes_detector_config(monkeypatch, tmp_path):
    config_path = tmp_path / "prooflayer.yaml"
    config_path.write_text(
        """
detector:
  enabled: true
  url: http://detector.local:8088
  timeout_ms: 123
response:
  report_dir: ./config-reports
""",
        encoding="utf-8",
    )
    captured = {}

    class FakeProxy:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def start(self):
            raise KeyboardInterrupt

        def stop(self):
            captured["stopped"] = True

    monkeypatch.setattr("prooflayer.runtime.transport.ProofLayerTransportProxy", FakeProxy)

    exit_code = cli.cmd_proxy(
        Namespace(
            listen_port=8080,
            backend_port=8081,
            backend_host="127.0.0.1",
            config=str(config_path),
            rules_dir=None,
            report_dir=None,
        )
    )

    assert exit_code == cli.EXIT_ALLOW
    assert captured["detector_url"] == "http://detector.local:8088"
    assert captured["detector_timeout_ms"] == 123
    assert captured["report_dir"] == "./config-reports"
    assert captured["stopped"] is True

