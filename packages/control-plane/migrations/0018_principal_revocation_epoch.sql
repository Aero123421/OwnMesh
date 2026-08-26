-- Separate "authority was removed" from "a token was reissued" (#162).
--
-- `credential_generation` advances on every OAuth credential issuance,
-- including a healthy refresh rotation. Binding device operations to it made a
-- routine 15-minute refresh terminally invalidate work that was merely waiting
-- for a device to reconnect, reported as a non-retryable credential mismatch —
-- indistinguishable from a real revocation.
--
-- `revocation_epoch` advances only when authority is intentionally removed:
-- explicit token revocation, refresh-family reuse detection, or account/session
-- invalidation. Operations bind to this epoch, so revocation still invalidates
-- every operation authorized by the affected credential family while a routine
-- rotation leaves already-authorized work valid.
--
-- `revocation_reason` records which bounded cause advanced the epoch so the
-- public error can name it without exposing tokens or family identifiers.
PRAGMA foreign_keys = ON;

ALTER TABLE principals
  ADD COLUMN revocation_epoch INTEGER NOT NULL DEFAULT 1
  CHECK (revocation_epoch >= 1);

ALTER TABLE principals
  ADD COLUMN revocation_reason TEXT;
