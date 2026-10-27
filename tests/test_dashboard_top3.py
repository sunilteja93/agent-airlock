from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_top3_dashboard_compiles():
    source = (ROOT / "dashboard_top3.py").read_text()
    compile(source, str(ROOT / "dashboard_top3.py"), "exec")
