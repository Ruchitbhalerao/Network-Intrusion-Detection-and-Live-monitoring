"""Stage 0 smoke test.

This is not a feature test. It only verifies that the project package can be
imported and that pytest is wired up correctly. Real tests for config,
parsing, the database, detection rules, dedup, and the API arrive in later
stages.
"""

import nids


def test_package_imports():
    assert nids is not None


def test_subpackages_import():
    import nids.detectors
    import nids.web

    assert nids.detectors is not None
    assert nids.web is not None
