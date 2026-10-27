"""Human-readable action lineage for the hackathon demo."""

from airlock.authority import Decision
from airlock.contract import TaskContract
from airlock.policy import PolicyDecision
from airlock.worker import WorkerProposal


def render_trace(*, contract: TaskContract, proposal: WorkerProposal, decision: PolicyDecision) -> str:
    required = ", ".join(sorted(decision.required_capabilities)) or "(none)"
    missing = ", ".join(sorted(decision.missing_capabilities)) or "(none)"
    allowed = ", ".join(sorted(contract.allowed_capabilities)) or "(none)"
    verdict = "ALLOW" if decision.decision is Decision.ALLOW else "BLOCK"

    return f"""
AIRLOCK ACTION TRACE
====================
Trusted goal:        {contract.goal}
Contract allows:     {allowed}

Proposal source:     {proposal.source}
Proposed action:     {proposal.action}
Required capability: {required}
Missing authority:   {missing}

Decision:            {verdict}
Reason:              {decision.reason}

Worker rationale:
{proposal.rationale}
""".strip()
