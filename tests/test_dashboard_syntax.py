from pathlib import Path


def test_dashboard_source_compiles():
    dashboard = Path(__file__).resolve().parents[1] / "dashboard.py"
    compile(dashboard.read_text(), str(dashboard), "exec")
