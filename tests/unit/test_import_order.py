"""Import-order regression: an `enrichment` submodule must load first.

``core.outbox`` and ``core.engine`` reference ``IncidentEnricher`` only in
annotations. When those were runtime imports, importing any ``enrichment``
submodule first closed the cycle (``enrichment.service`` -> ``core`` ->
``core.engine`` -> ``enrichment.service``) and raised ImportError. The live
OpenCTI smoke tool imports ``enrichment.geo`` first, which is how it surfaced.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import opencanary_correlator

SCRIPT = (
    "from opencanary_correlator.enrichment.geo import public_address;"
    "assert public_address('8.8.8.8') is not None"
)


def test_enrichment_submodule_can_be_imported_first() -> None:
    """A fresh interpreter must import `enrichment.geo` without a cycle."""
    src = Path(opencanary_correlator.__file__).resolve().parents[1]
    env = {**os.environ, "PYTHONPATH": str(src)}
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and literal code
        [sys.executable, "-c", SCRIPT],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
