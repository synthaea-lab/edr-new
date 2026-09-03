# server/assistant — Analyst AI Assistant

Server-side LLM assistance for the analyst, built on the grounding rule recorded in
docs/detection/ml.md: **the LLM narrates and navigates structured evidence; it never
scores, never judges, never runs on the endpoint.**

Planned capabilities, in trust order:
1. **Case narratives** — generate the human-readable story of a case from its
   evidence graph (detections + attributions + timeline), with every claim linked to
   the underlying record; regenerated on evidence change.
2. **Natural-language navigation** — "show hosts where this hash ran last week"
   compiled to hunt/graph queries the analyst can see and edit before running.
3. **Triage drafting** — suggested next steps and draft disruption playbook choices,
   always as proposals requiring the analyst's action; the assistant holds no
   execution authority of its own.

Constraints: assistant output is visibly labeled, grounded citations are mandatory,
prompts/outputs land in the audit log, and tenant data never trains shared models.
