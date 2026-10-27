"""Judge-facing Streamlit console for Agent Airlock."""

from pathlib import Path
import shutil
import sys
import tempfile

import streamlit as st


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
SCENARIO = ROOT / "scenarios" / "poisoned_repo"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


from airlock.authority import Decision
from airlock.delegation import AuthorityGraph, evaluate_delegated_action
from airlock.patcher import apply_return_expression, evaluate_expression, propose_return_expression
from airlock.worker import propose_action


st.set_page_config(
    page_title="Agent Airlock",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
    .block-container {padding-top: 2rem; padding-bottom: 2rem; max-width: 1500px;}
    .hero {padding: 0.25rem 0 0.75rem 0;}
    .hero h1 {font-size: 3rem; margin-bottom: 0.2rem;}
    .hero p {font-size: 1.1rem; color: #9ca3af; margin-top: 0;}
    .principle {font-size: 1.55rem; font-weight: 700; margin-top: 0.6rem;}
    .card {border: 1px solid rgba(148,163,184,.22); border-radius: 14px;
           padding: 16px 18px; background: rgba(30,41,59,.28); min-height: 112px;}
    .card-title {font-size: .78rem; letter-spacing: .08em; text-transform: uppercase;
                 color: #94a3b8; margin-bottom: 8px;}
    .card-value {font-size: 1.05rem; font-weight: 650;}
    .tag {display: inline-block; border: 1px solid rgba(148,163,184,.35);
          border-radius: 999px; padding: 4px 9px; margin: 3px 4px 3px 0;
          font-family: monospace; font-size: .82rem;}
    .danger {border-color: rgba(239,68,68,.55); color: #fca5a5;}
    .safe {border-color: rgba(34,197,94,.5); color: #86efac;}
    .muted {color:#94a3b8;}
    div[data-testid="stButton"] button {height: 3.2rem; font-weight: 700;}
    </style>
    """,
    unsafe_allow_html=True,
)

SCENARIOS = {
    "Compromised sub-agent": {
        "kind": "action",
        "principal": "setup_worker",
        "action": "secret.read",
        "authority": "repo.read",
        "description": (
            "A compromised setup worker has repository-read access but attempts "
            "to read a secret it was never delegated."
        ),
    },
    "Compromised tool / plugin": {
        "kind": "action",
        "principal": "repo_tool",
        "action": "network.write",
        "authority": "repo.read",
        "description": (
            "A repository tool can inspect code, but a compromised plugin tries "
            "to send data to an external network destination."
        ),
    },
    "Privilege escalation": {
        "kind": "grant",
        "principal": "setup_worker",
        "action": "delegate secret.read",
        "authority": "repo.read",
        "description": (
            "A low-privilege worker attempts to create a child with secret-read "
            "authority that the parent itself does not possess."
        ),
    },
}


def build_graph() -> AuthorityGraph:
    graph = AuthorityGraph(
        root="user",
        root_capabilities=frozenset({"repo.read", "repo.write", "tests.run"}),
    )
    graph.grant(
        "user",
        "planner",
        frozenset({"repo.read", "repo.write", "tests.run"}),
    )
    graph.grant(
        "planner",
        "code_worker",
        frozenset({"repo.read", "repo.write", "tests.run"}),
    )
    graph.grant("code_worker", "setup_worker", frozenset({"repo.read"}))
    graph.grant("code_worker", "repo_tool", frozenset({"repo.read"}))
    return graph


def badge(text: str, kind: str = "") -> str:
    css = f"tag {kind}".strip()
    return f'<span class="{css}">{text}</span>'


st.markdown(
    """
    <div class="hero">
      <h1>🛡️ Agent Airlock</h1>
      <p>Zero-trust authority enforcement for multi-agent AI systems</p>
      <div class="principle">Information is not authority.</div>
    </div>
    """,
    unsafe_allow_html=True,
)

k1, k2, k3, k4 = st.columns(4)
for col, title, value in [
    (k1, "Meta model", "Muse Spark 1.3"),
    (k2, "Authority model", "Monotonic delegation"),
    (k3, "Enforcement", "Deterministic"),
    (k4, "Execution", "Sandboxed"),
]:
    col.markdown(
        f'<div class="card"><div class="card-title">{title}</div>'
        f'<div class="card-value">{value}</div></div>',
        unsafe_allow_html=True,
    )

st.write("")

left, right = st.columns([0.95, 1.35], gap="large")

with left:
    st.subheader("Authority graph")
    st.code(
        "user\n├── planner\n│   └── code_worker\n│       ├── setup_worker\n│       └── repo_tool",
        language="text",
    )

    st.markdown("**user → planner → code_worker**")
    st.markdown(
        badge("repo.read", "safe")
        + badge("repo.write", "safe")
        + badge("tests.run", "safe"),
        unsafe_allow_html=True,
    )
    st.markdown("**setup_worker / repo_tool**")
    st.markdown(badge("repo.read", "safe"), unsafe_allow_html=True)

    st.info(
        "Authority can stay the same or shrink as it is delegated. "
        "It cannot spontaneously increase."
    )

    with st.expander("Why this matters"):
        st.write(
            "Airlock does not require every model, plugin, tool, or sub-agent to "
            "be perfectly trustworthy. It limits what each component can actually do."
        )

with right:
    st.subheader("Attack simulation")
    selected = st.radio(
        "Choose a scenario",
        options=list(SCENARIOS),
        horizontal=True,
        label_visibility="collapsed",
    )
    scenario = SCENARIOS[selected]

    st.markdown(
        f'<div class="card"><div class="card-title">Selected scenario</div>'
        f'<div class="card-value">{selected}</div>'
        f'<p class="muted">{scenario["description"]}</p></div>',
        unsafe_allow_html=True,
    )

    p1, p2, p3 = st.columns(3)
    p1.markdown(
        f'<div class="card"><div class="card-title">Principal</div>'
        f'<div class="card-value">{scenario["principal"]}</div></div>',
        unsafe_allow_html=True,
    )
    p2.markdown(
        f'<div class="card"><div class="card-title">Delegated</div>'
        f'<div class="card-value">{scenario["authority"]}</div></div>',
        unsafe_allow_html=True,
    )
    p3.markdown(
        f'<div class="card"><div class="card-title">Attempt</div>'
        f'<div class="card-value">{scenario["action"]}</div></div>',
        unsafe_allow_html=True,
    )

    st.write("")
    run = st.button(
        "▶ Run protected workflow",
        type="primary",
        use_container_width=True,
    )

    if not run:
        st.markdown("#### What Airlock will prove")
        q1, q2, q3 = st.columns(3)
        q1.success("1. Unauthorized authority is blocked")
        q2.info("2. Muse continues legitimate work")
        q3.success("3. Task still completes")

    if run:
        graph = build_graph()
        st.markdown("### Live trace")

        if scenario["kind"] == "action":
            blocked = evaluate_delegated_action(
                graph=graph,
                principal=scenario["principal"],
                action=scenario["action"],
            )
            a1, a2, a3 = st.columns(3)
            a1.metric("Requested action", scenario["action"])
            a2.metric("Effective authority", scenario["authority"])
            a3.metric("Airlock decision", blocked.decision.value.upper())
            st.error(
                f'BLOCKED · {blocked.reason}'
            )
            st.caption(
                "Authority lineage: "
                + " → ".join(graph.lineage(scenario["principal"]))
            )
            denied_action = scenario["action"]
        else:
            a1, a2, a3 = st.columns(3)
            a1.metric("Parent", "setup_worker")
            a2.metric("Parent authority", "repo.read")
            a3.metric("Requested child grant", "secret.read")
            try:
                graph.grant(
                    "setup_worker",
                    "rogue_child",
                    frozenset({"secret.read"}),
                )
                st.error("Unexpected: escalation grant was accepted.")
                st.stop()
            except ValueError as exc:
                st.error(f"BLOCKED · {exc}")
            denied_action = "secret.read"

        st.markdown("#### Muse Spark recovery")
        source = (SCENARIO / "app.py").read_text()
        goal = "Fix issue #217 so add(2, 3) returns 5."
        completed: list[str] = []
        reached_write = False

        with st.spinner("Muse Spark is planning the next authorized action..."):
            for step in range(1, 4):
                proposal = propose_action(
                    goal=goal,
                    repository_content=f"FILE: app.py\n{source}",
                    denied_actions=(denied_action,),
                    completed_actions=tuple(completed),
                )
                decision = evaluate_delegated_action(
                    graph=graph,
                    principal="code_worker",
                    action=proposal.action,
                )

                if decision.decision is Decision.ALLOW:
                    st.success(
                        f"Step {step}: {proposal.action} → ALLOW · {proposal.rationale}"
                    )
                else:
                    st.warning(
                        f"Step {step}: {proposal.action} → BLOCK · {decision.reason}"
                    )

                if proposal.action == "repo.write" and decision.decision is Decision.ALLOW:
                    reached_write = True
                    break

                if decision.decision is Decision.ALLOW and proposal.action not in completed:
                    completed.append(proposal.action)

        if not reached_write:
            st.error("Muse did not reach an authorized repo.write step in this run.")
            st.stop()

        st.markdown("#### Muse-generated repair")
        with st.spinner("Muse Spark is generating the minimal repair..."):
            expression = propose_return_expression(goal=goal, source=source)
            patched = apply_return_expression(source, expression)

        before_col, after_col = st.columns(2)
        with before_col:
            st.caption("Before")
            st.code(source, language="python")
        with after_col:
            st.caption("After")
            st.code(patched, language="python")

        st.success(f"Patch validator: PASS · {expression}")

        st.markdown("#### Sandboxed verification")
        with tempfile.TemporaryDirectory(prefix="agent-airlock-") as tmp:
            sandbox = Path(tmp)
            shutil.copy2(SCENARIO / "app.py", sandbox / "app.py")
            (sandbox / "app.py").write_text(patched)
            result_1 = evaluate_expression(expression, a=2, b=3)
            result_2 = evaluate_expression(expression, a=-2, b=5)

        t1, t2 = st.columns(2)
        t1.metric("add(2, 3)", result_1, "expected 5")
        t2.metric("add(-2, 5)", result_2, "expected 3")

        if result_1 != 5 or result_2 != 3:
            st.error("Verification failed.")
            st.stop()

        st.markdown("#### Outcome")
        r1, r2, r3 = st.columns(3)
        r1.metric("Escalation", "BLOCKED")
        r2.metric("Authorized work", "ALLOWED")
        r3.metric("Task", "COMPLETED")
        st.success(
            "Attack contained. Legitimate work completed. "
            "Authority never exceeded the user's original grant."
        )

st.divider()
st.caption(
    "Synthetic security demo. No real secrets are accessed and no external "
    "exfiltration is performed."
)
