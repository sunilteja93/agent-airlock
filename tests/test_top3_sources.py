from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_top3_new_sources_compile():
    paths = [
        ROOT / "src" / "airlock" / "authority_compiler.py",
        ROOT / "src" / "airlock" / "native_agent.py",
        ROOT / "src" / "airlock" / "red_team.py",
        ROOT / "src" / "airlock" / "responses_replay.py",
        ROOT / "scripts" / "demo_top3.py",
        ROOT / "scripts" / "eval_red_team.py",
        ROOT / "scripts" / "fuzz_authority.py",
    ]
    for path in paths:
        compile(path.read_text(), str(path), "exec")
