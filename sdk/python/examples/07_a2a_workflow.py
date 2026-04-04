"""
Advanced Agent-to-Agent (A2A) Workflow with Clampd Security

clampd.agent() sets up the delegation scope automatically.
@clampd.guard() handles per-tool-call delegation internally.
Developers don't need to touch enter_delegation/exit_delegation directly.

Run: python examples/07_a2a_workflow.py
"""
import sys

sys.path.insert(0, ".")

from examples.mock_gateway import install_mock_gateway

install_mock_gateway()

import os

import clampd
from clampd.client import ClampdBlockedError

clampd.init(
    agent_id="orchestrator",
    api_key=os.environ.get("CLAMPD_API_KEY", ""),
    gateway_url=os.environ.get("CLAMPD_GATEWAY_URL", "http://localhost:8080"),
    # Per-agent secrets: each agent authenticates independently.
    # Kill/rate-limit/EMA operate per-agent, not shared.
    agents={
        "orchestrator": os.environ.get("CLAMPD_SECRET_orchestrator"),
        "research-agent": os.environ.get("CLAMPD_SECRET_research_agent"),
        "analysis-agent": os.environ.get("CLAMPD_SECRET_analysis_agent"),
        "writer-agent": os.environ.get("CLAMPD_SECRET_writer_agent"),
    },
)


# ── Guarded tools — each has its own agent_id ─────────────────────

@clampd.guard("web.search", agent_id="research-agent")
def search_web(query: str) -> dict:
    print(f'    [search] Searching: "{query}"')
    return {
        "results": [
            "Clampd: Runtime security for AI agents - clampd.dev",
            "AI Agent Security Best Practices - OWASP",
            "Tool Call Interception Patterns - arxiv.org",
        ]
    }


@clampd.guard("data.analyze", agent_id="analysis-agent")
def analyze_data(data: list, focus: str) -> dict:
    print(f"    [analyze] Analyzing {len(data)} items")
    return {
        "summary": (
            f'Analysis of {len(data)} sources on "{focus}": '
            "Runtime security is critical. Key approaches: tool call "
            "interception, prompt scanning, delegation chain tracking."
        ),
        "confidence": 0.92,
    }


@clampd.guard("doc.write", agent_id="writer-agent", check_response=True)
def write_report(title: str, analysis: str, sources: list) -> dict:
    print(f'    [write] Generating report: "{title}"')
    source_list = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(sources))
    return {"report": f"# {title}\n\n{analysis}\n\n## Sources\n{source_list}"}


@clampd.guard("rm_rf", agent_id="rogue-agent")
def delete_files(path: str) -> str:
    return f"Deleted: {path}"


# ── Orchestrator — just use clampd.agent() for the scope ──────────

def main():
    print("=== A2A Workflow Demo (Python) ===\n")

    # clampd.agent() sets up the delegation scope. That's it.
    # All @guard() calls inside inherit the chain automatically.
    with clampd.agent("orchestrator"):

        # Step 1: Research
        print("Step 1: Research Agent")
        result = search_web(query="AI agent security")
        sources = result["results"]
        print(f"  Found {len(sources)} sources\n")

        # Step 2: Analysis
        print("Step 2: Analysis Agent")
        analysis = analyze_data(data=sources, focus="AI agent security")
        print(f"  Confidence: {analysis['confidence']}\n")

        # Step 3: Writing
        print("Step 3: Writer Agent")
        report = write_report(
            title="AI Agent Security",
            analysis=analysis["summary"],
            sources=sources,
        )
        print("  Report generated\n")

        # Step 4: Blocked dangerous action
        print("Step 4: Rogue agent tries to delete files...")
        try:
            delete_files(path="/important-data")
        except ClampdBlockedError as e:
            print("  BLOCKED by Clampd!")
            print(f"  Reason: {e.response.denial_reason}")
            print(f"  Risk: {e.response.risk_score}\n")

        print("=== Final Report ===\n")
        print(report["report"])


if __name__ == "__main__":
    main()
