# Investigation Notebook design system

The selected visual target is `investigation-notebook-reference.png` (1487 × 1058).

## Visual hierarchy

- Persistent 184 px navigation rail with the active investigation item highlighted in violet.
- 48 px trust strip communicating local-node health, data sovereignty, model-gateway retention, policy, and time.
- Main investigation canvas uses a vertical numbered narrative: hypothesis, local findings, baseline comparison, minimized AI handoff, and recommended actions.
- A 290–310 px evidence rail contains the evidence index, transmission ledger, and fields removed.
- Persistent bottom actions expose the primary investigation CTA, ledger inspection, local export, and approved response workflow.

## Tokens

- Canvas: near-black charcoal (`#0b0d0f`–`#111417`).
- Elevated/selected surfaces: graphite and muted violet (`#262039`).
- Primary text: cool white (`#f2f2f4`); secondary: cool gray (`#9b9da5`).
- Accent: violet (`#805eea`); local/privacy success: teal (`#65d5bd`); high severity: coral (`#ff684c`).
- Borders are subtle and low-contrast. Depth comes from spacing and surface changes, not shadows.
- UI type is a clean neutral sans; evidence IDs use a restrained monospaced face.

## Interaction rules

- Evidence identifiers are interactive and open their local details.
- Starting an investigation visibly advances local collection and minimization before any gateway step.
- The transmission ledger always exposes included/removed fields, hashes, token counts, retention mode, region, latency, and result.
- Model failure preserves the alert and local findings.
- Response actions require an explicit human approval step.
