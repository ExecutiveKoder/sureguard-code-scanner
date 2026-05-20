from sureguard_code_scanner.models import Ecosystem
from sureguard_code_scanner.sources.registries import typosquat_candidates


def test_requestz_flags_requests():
    assert "requests" in typosquat_candidates("requestz", Ecosystem.PYPI)


def test_real_package_no_candidates():
    assert typosquat_candidates("requests", Ecosystem.PYPI) == []


def test_far_distance_not_flagged():
    assert typosquat_candidates("completely-unrelated-name", Ecosystem.PYPI) == []


def test_npm_axious_flags_axios():
    assert "axios" in typosquat_candidates("axious", Ecosystem.NPM)
