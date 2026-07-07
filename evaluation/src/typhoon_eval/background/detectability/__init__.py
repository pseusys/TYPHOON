"""Held-out detectability tests for Part 3 (Tests A / B / D / E / F).

Each test models a distinct adversary threat model and uses k-fold
cross-validation so reported numbers reflect held-out performance, never
training-set memorisation.  Test C (open-world confidence-threshold
detection) is the primary blending metric and lives in ``ml_blending.py``;
the tests here cover the remaining threat models, grouped by paradigm:

  * ``pair_binary``  — Test A (closed two-class pair detection)
  * ``closed_world`` — Test B (closed-world n+1-class)
  * ``open_set``     — Tests D / E / F (open-set / one-class)

``cli.py`` loads the shared Barradas feature corpus once and orchestrates all
five, writing a combined ``detection_results.json``.  Run via
``python -m typhoon_eval.background.detectability``.
"""
