# ztaf-registry

The registry reference for the Zero-Trust Agent Framework: published mandates, agent entries, capability provenance, and signed revocation status lists, with a CLI.

| Field | Value |
|---|---|
| Authority | Reference implementation — normative revocation semantics: [ztaf-spec](https://github.com/Zero-TAF/ztaf-spec) (mandate format document §5) |
| Tier | T4 (realization) |
| Wave | W4 |
| Version | 0.1.0 |
| Status | Active |
| Licence | MIT |

## What this repository owns

- `ztaf_registry/registry.py` — the file-backed registry: mandate publication and resolution; **revocation with down-chain propagation** (MAN-6: descendants fall with the parent, ancestors survive); agent entries shaped to carry the **Agentic Operations bootstrap output** (subject, card reference, mandate binding — produced by `ztaf-reference-harness` `ztaf_harness.ao.bootstrap`); capability provenance entries (CON-4); **signed status lists** in exactly the format `ztaf_mandate.revocation.StatusChecker` verifies.
- `ztaf_registry/cli.py` — `ztaf-registry init | publish | revoke | register-agent | add-capability | status-list | resolve | agents`.
- `tests/` — the full cycle: publish → resolve → revoke-propagation → signed status list verified and stale-list rejection, through the real `StatusChecker`.

## What this repository does not own

- Normative semantics — [ztaf-spec](https://github.com/Zero-TAF/ztaf-spec); chain verification — [ztaf-mandate](https://github.com/Zero-TAF/ztaf-mandate); the decision point — [ztaf-reference-harness](https://github.com/Zero-TAF/ztaf-reference-harness).
- Production availability: a real registry is on the decision point's fail-closed path (ENF-3 — registry unavailability denies); HA deployment is an operator concern, not a reference concern.

## Running

```bash
pip install cryptography   # the only dependency
python -m unittest discover -s tests -v

python -m ztaf_registry.cli init --registry reg.json
python -m ztaf_registry.cli publish --registry reg.json --mandate-file agent-mandate.json
python -m ztaf_registry.cli register-agent --registry reg.json --subject refund-agent-42 \
    --mandate-id ZT-MND-refund-agent-42 --grade TG-2 --card card.json
python -m ztaf_registry.cli status-list --registry reg.json \
    --key-seed $(python -c 'print("de"*32)') --kid demo-operations-root
```
