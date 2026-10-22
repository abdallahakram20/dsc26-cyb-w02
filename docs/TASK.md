# Task: dsc26-cyb-w02, Rawaj Pay threat model as code

DSC Summer Internship 2026, Cybersecurity track, Week 2 (STRIDE). Python 3.12, PyYAML 6.0.3, pytest 9.1.1.

## Checklist
- [x] `tmcheck/core.py`: load_model, applicable, validate, crossing_flows, coverage_gaps, policy_findings, rank
- [x] `tmcheck/__main__.py`: `python -m tmcheck MODEL.yaml` -> JSON (issues, gaps, policy, ranked); exit 2 unloadable, 1 findings, 0 clean
- [x] own tests for every rule: `tests/test_spec.py`
- [x] `models/rawaj_scoring.yaml`: add a threat for each of the 11 gaps (unique titles, 15+ chars), fix the 2 policy findings, delete nothing
- [ ] `AI_USAGE.md`: sections `## Tools`, `## What AI got wrong`, `## In my own words` (last one written without AI)
- [ ] push, then press Submit for grading on DSC Hex

## Run
    uv venv --python 3.12 && source .venv/bin/activate
    uv pip install -r requirements.txt
    python -m pytest -q
