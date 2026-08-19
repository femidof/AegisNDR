# Design QA — Investigation Notebook

- Source visual truth: `docs/design/investigation-notebook-reference.png`
- Implementation screenshot: `docs/design/implementation-final.png`
- State: default Investigation Notebook with completed local findings and AI assessment
- Viewport / CSS size: 1487 × 1058 px
- Source pixels: 1487 × 1058 px
- Implementation pixels: 1487 × 1058 px
- Device scale factor: 1
- Density normalization: none required

## Findings

No actionable P0, P1, or P2 mismatches remain.

The implementation preserves the source hierarchy and proportions: 184 px dark navigation rail, compact trust strip, five-step vertical investigation narrative, evidence/transmission context rail, and persistent action dock. The violet, teal, coral, graphite, and cool-white token relationships match the source closely. The real Phosphor icon set replaces the mock's line icons consistently; no raster placeholders, handcrafted SVGs, CSS drawings, gradients, emoji, or fake assets are present.

## Required fidelity surfaces

- Fonts and typography: neutral sans-serif with restrained monospace evidence IDs matches the intended visual character. Heading weights, compact metadata, label hierarchy, wrapping, and truncation are consistent with the reference. The implementation is slightly crisper and more compact than the generated-image text, which is acceptable for legibility.
- Spacing and layout rhythm: overall frame, primary columns, timeline cadence, separators, evidence rail, and dock placement match. Content uses the full viewport without hidden persistent controls or horizontal overflow at the target size.
- Colors and visual tokens: near-black canvas, graphite surfaces, low-contrast borders, violet actions, teal privacy states, and coral severity accents match the source semantics and contrast relationships.
- Image quality and asset fidelity: the source contains no raster artwork. All visible icons use a coherent installed icon library at appropriate sizes; there are no placeholder or approximate image assets.
- Copy and content: the alert, evidence IDs, baseline values, MITRE technique, zero-retention boundary, removed fields, ledger, and human-review language match the source and product specification. Navigation terminology expands beyond the mock where needed to support the PDF-defined product flow.

## Full-view comparison evidence

The source and implementation were opened together at identical pixel dimensions. Major-region proportions, information hierarchy, timeline density, context-rail anatomy, persistent controls, and dark theme visibly align. The implementation intentionally uses working product copy and standard icons rather than reproducing minor generated-text artifacts.

Focused crops were not required: the 1487 × 1058 source and implementation renders make typography, evidence chips, ledger values, icons, and controls legible in the full-view comparison.

## Comparison history

### Pass 1

- Finding [P2]: the first raw Chrome capture used an outer-window size whose inner viewport was shorter than the source, leaving blank space below the application.
- Fix: captured through a browser context with an explicit 1487 × 1058 CSS viewport and device scale factor 1.
- Post-fix evidence: `docs/design/implementation-pass-2.png`; the application fills the normalized viewport and all persistent actions remain visible.
- Finding [P2]: local API fallback requests generated console 404s when the API was not running.
- Fix: made API connectivity explicit through `VITE_LOCAL_API_ENABLED`/`VITE_LOCAL_API_BASE`, corrected the endpoints to `/api/v1`, and added a no-request deterministic demo mode.
- Post-fix evidence: final browser run reported zero console and page errors.

### Final pass

- Browser-rendered evidence: `docs/design/implementation-final.png`
- Target viewport: 1487 × 1058, device scale factor 1
- Primary interactions tested: alert queue opened; alert selected; investigation notebook opened; all eight investigation steps completed; transmission ledger opened and closed; alert acknowledged; case created; all nine navigation destinations opened.
- Responsive check: 1024 × 768 layout checked with no horizontal document overflow.
- Console and page errors: none.
- Production build: passed.
- Sites worker/package tests: 4/4 passed.
- Backend security/integration tests: 12/12 passed.

## Follow-up polish

- [P3] The implementation's UI text is slightly smaller and sharper than the ImageGen mock; this improves density and legibility but could be loosened in a future visual-only iteration.
- [P3] Product-spec navigation differs from a few mock labels so the runnable MVP exposes the required Alerts, Traffic, Sensors, AI Transmissions, Audit, and Settings workflows.

## Implementation checklist

- [x] Target viewport and density normalized.
- [x] Source and rendered implementation compared together.
- [x] Core alert-to-investigation journey works.
- [x] Transmission boundary and evidence provenance remain inspectable.
- [x] Persistent controls remain visible.
- [x] Responsive and console checks pass.

final result: passed
