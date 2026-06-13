"""Top-level adversarial eval orchestration."""

from pathlib import Path
from typing import Iterable, List, Optional

from .adversarial_suite import AdversarialSuite
from .garak_runner import GarakRunner
from .langgraph_target import LangGraphEvalTarget
from .promptfoo_runner import PromptFooRunner
from .report import EvalFinding, EvalReport, ReportGenerator


class EvalRunner:
    """Orchestrate GARAK, PromptFoo, and built-in ProofLayer probes."""

    def __init__(
        self,
        garak_runner: Optional[GarakRunner] = None,
        promptfoo_runner: Optional[PromptFooRunner] = None,
        adversarial_suite: Optional[AdversarialSuite] = None,
        report_generator: Optional[ReportGenerator] = None,
    ) -> None:
        """Initialize the eval runner and its sub-runners."""
        self.garak_runner = garak_runner or GarakRunner()
        self.promptfoo_runner = promptfoo_runner or PromptFooRunner()
        self.adversarial_suite = adversarial_suite or AdversarialSuite()
        self.report_generator = report_generator or ReportGenerator()

    def run_builtin_suite(self, target: LangGraphEvalTarget) -> EvalReport:
        """Run only the built-in ProofLayer adversarial suite."""
        findings = self.adversarial_suite.run(target)
        return self.report_generator.build(target.name, findings)

    def run_all(
        self,
        target: LangGraphEvalTarget,
        output_dir: Path,
        endpoint_url: Optional[str] = None,
        promptfoo_config: Optional[Path] = None,
        garak_probes: Optional[Iterable[str]] = None,
    ) -> EvalReport:
        """Run available eval surfaces and generate JSON plus Markdown reports."""
        output_dir.mkdir(parents=True, exist_ok=True)
        findings: List[EvalFinding] = []
        findings.extend(self.adversarial_suite.run(target))
        if endpoint_url is not None:
            findings.extend(
                self.garak_runner.run(
                    endpoint_url=endpoint_url,
                    output_dir=output_dir / "garak",
                    probes=garak_probes,
                )
            )
        if promptfoo_config is not None:
            findings.extend(
                self.promptfoo_runner.run(
                    config_path=promptfoo_config,
                    output_path=output_dir / "promptfoo-results.json",
                )
            )
        report = self.report_generator.build(target.name, findings)
        self.report_generator.to_json(report, output_dir / "findings.json")
        self.report_generator.to_markdown(report, output_dir / "findings.md")
        return report
