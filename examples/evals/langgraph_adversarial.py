"""Run the built-in ProofLayer adversarial suite against a LangGraph agent.

This example is intentionally dependency-light: it uses LangGraph and the
ProofLayer middleware, but no external LLM provider. GARAK and PromptFoo runs
are available through prooflayer.evals.EvalRunner.run_all when an
OpenAI-compatible endpoint and PromptFoo config are supplied.
"""

from pathlib import Path
from typing import Dict, TypedDict

from langgraph.graph import END, StateGraph

from prooflayer.evals import EvalRunner, LangGraphEvalTarget
from prooflayer.integrations.langgraph import SecurityConfig, SecurityMiddleware


class DemoState(TypedDict):
    """State for the local demo graph."""

    input: str
    answer: str


def answer_question(state: DemoState) -> Dict[str, str]:
    """Return a deterministic answer for eval demonstration."""
    return {"answer": f"handled: {state['input']}"}


def build_secured_graph():
    """Build a ProofLayer-secured demo LangGraph."""
    graph = StateGraph(DemoState)
    graph.add_node("answer", answer_question)
    graph.set_entry_point("answer")
    graph.add_edge("answer", END)

    middleware = SecurityMiddleware(
        SecurityConfig(
            prompt_injection="block",
            jailbreak="block",
            exfil="block",
            scope_drift="warn",
            state_manipulation="block",
            multi_turn="warn",
            emit_to=["stdout"],
        )
    )
    return middleware.wrap(graph.compile())


def main() -> None:
    """Run the built-in adversarial suite and print a compact summary."""
    target = LangGraphEvalTarget(build_secured_graph(), name="local-demo-langgraph")
    output_dir = Path("security-reports/evals/langgraph")
    report = EvalRunner().run_all(target, output_dir=output_dir)
    print(
        "ProofLayer eval complete: "
        f"{report.passed_count} passed, {report.failed_count} failed, "
        f"{len(report.findings)} total"
    )
    print(f"Reports written to: {output_dir}")
    for finding in report.findings[:5]:
        status = "PASS" if finding.passed else "FAIL"
        print(f"{status} {finding.id}: {finding.outcome}")


if __name__ == "__main__":
    main()
