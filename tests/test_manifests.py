from sureguard_mcp.manifests import (
    parse_package_json,
    parse_pyproject_toml,
    parse_requirements_txt,
)
from sureguard_mcp.models import Ecosystem


def test_requirements_txt_basic():
    content = """
    # comment
    requests==2.31.0
    httpx>=0.27.0
    unpinned-pkg
    -r other.txt
    """
    pkgs = parse_requirements_txt(content)
    names = {p.name: p for p in pkgs}
    assert names["requests"].version == "2.31.0"
    assert names["httpx"].version == "0.27.0"
    assert names["unpinned-pkg"].version is None
    assert all(p.ecosystem == Ecosystem.PYPI for p in pkgs)


def test_package_json_dependencies():
    content = """
    {
      "dependencies": {"axios": "^1.7.0", "express": "4.19.2"},
      "devDependencies": {"jest": "29.0.0"}
    }
    """
    pkgs = parse_package_json(content)
    by_name = {p.name: p.version for p in pkgs}
    assert by_name["axios"] == "1.7.0"
    assert by_name["express"] == "4.19.2"
    assert by_name["jest"] == "29.0.0"


def test_pyproject_dependencies():
    content = """
[project]
name = "demo"
dependencies = ["httpx>=0.27.0", "pydantic==2.7.0", "anyio"]
"""
    pkgs = parse_pyproject_toml(content)
    by_name = {p.name: p.version for p in pkgs}
    assert by_name["httpx"] == "0.27.0"
    assert by_name["pydantic"] == "2.7.0"
    assert by_name["anyio"] is None
