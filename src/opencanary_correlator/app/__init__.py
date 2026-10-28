"""Composition root: arguments, wiring, description and the process runner.

The package is split by responsibility so each part can be read and tested on
its own:

* `parser` — flags, settings loading and the startup error type;
* `wiring` — what the settings turn into (channels, enrichment, listeners);
* `describe` — the secret-free summary printed by `--check-config`;
* `runner` — the event loop, signal handling and the exit codes.

`opencanary_correlator.cli` re-exports all of it, so imports keep working.
"""

from __future__ import annotations

__all__: list[str] = []
