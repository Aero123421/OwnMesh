# OwnMesh v1.0.1 — Historical notes (claims corrected)

> [!WARNING]
> The original v1.0.1 notes overstated specification completeness. In particular, they described several library, parser, and workflow skeletons as completed end-to-end features. Those claims are withdrawn. This documentation correction does not alter or replace the existing tag.

v1.0.1 established substantial runtime, control-plane, broker/session, profile, TUI, and security-test foundations, but it was not complete against the OwnMesh 1.0 DoD. At the audited v1.0.2 baseline, the CLI still had 43 generic stubs plus additional unsupported hard-error surfaces, and signing/provenance/release gating did not meet the documented standard.

For the corrected current scope, see:

- [`RELEASE_NOTES_v1.0.2.md`](./RELEASE_NOTES_v1.0.2.md)
- [`DOD_1.0.md`](./DOD_1.0.md)
- [`../release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json)

The v1.0.1 W-SIGN, W-LIVE-E2E, W-EXT-SEC, W-§12, and W-§14 waivers were deferrals/disclosures. They did not make the corresponding DoD items complete. Checksums were not artifact signatures, and CI/Security success was not structurally required by the original v1.0.1 release workflow.
