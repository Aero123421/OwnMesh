# ownmesh-transfer

Bounded, authenticated transfer core.

This crate intentionally provides no cloud relay, LAN discovery, or caller
consent/transport selection. A control-plane integration must authenticate and
bind an immutable `TransferGrant` before creating a `TransferPlan`.

The core transfers at most one 64 KiB chunk at a time, checks sequence, offset,
per-chunk SHA-256 and final SHA-256, and can persist a bounded owner-only
journal. Filesystem publication is deliberately delegated to a custody-aware
integration: this crate does not resurrect the former unsafe whole-file local
copy helper or silently overwrite a destination.
