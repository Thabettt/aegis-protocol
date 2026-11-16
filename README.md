# Aegis

A protocol for handing a file to another person through a server that is assumed to be hostile.

**Status: draft v3.0. Not audited. No formal proof. Do not use it to protect anyone at real risk.**

v2.1 was withdrawn after an audit found that several of its central claims did not hold. v3.0 is a redesign. The v2.1 documents remain in git history at commit `a531356`.

## Documents

Read in this order.

| # | Document | What it is |
|---|----------|------------|
| 1 | [Aegis_audit_report.md](Aegis_audit_report.md) | What was wrong with v2.1, what was kept, what was dismissed, and why |
| 2 | [Aegis_project_specification.md](Aegis_project_specification.md) | The v3.0 protocol. Normative. |
| 3 | [Aegis_research.md](Aegis_research.md) | Design rationale, security analysis, prior art |
| 4 | [Aegis_implementation_plan.md](Aegis_implementation_plan.md) | Milestones M0–M11, from executable model to audited release |

## Executable model

`model/aegis_v3_model.py` implements specification §3–§11 using only the Python standard library.

```bash
python model/aegis_v3_model.py
```

It checks its primitives against published RFC vectors, seals and opens shares in every mode, runs 45 negative cases, and writes `model/vectors_v3_provisional.json`.

The model shows the specification can be implemented as written and rejects what it should. It is not evidence that the design is secure, it is not constant-time, and it must never handle real secrets.

## Licence

See [LICENSE](LICENSE).
