//! Ephemeral E2E transfer cryptography.  Keys exist only for one transient
//! transfer WebSocket session and are never serialized, logged, or persisted.

use ownmesh_identity::verify_from_public_key_hex;
use ring::{aead, agreement, hkdf, rand};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"ownmesh-transfer-e2e-v1";
const EPHEMERAL_PROOF_DOMAIN: &str = "ownmesh-transfer-ephemeral-v1";

/// Strict Agent view of a Worker-issued transfer ticket. The Worker verifies
/// its HMAC and both Ed25519 proofs before upgrade; Agents independently
/// verify the proof for the peer key they are about to use for X25519.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentTransferTicket {
    pub v: u8,
    pub jti: String,
    pub session_nonce: String,
    pub transfer_id: String,
    pub tenant_id: String,
    pub principal_id: String,
    pub device_id: String,
    pub role: String,
    pub source_device_id: String,
    pub destination_device_id: String,
    pub source_workspace_id: String,
    pub destination_workspace_id: String,
    pub plan_sha256: String,
    pub epoch: u32,
    pub fence: u64,
    pub max_bytes: u64,
    pub exp: u64,
    pub source_device_public_key: String,
    pub destination_device_public_key: String,
    pub source_ephemeral_public_key: String,
    pub destination_ephemeral_public_key: String,
    pub source_ephemeral_signature: String,
    pub destination_ephemeral_signature: String,
}

impl AgentTransferTicket {
    /// Rejects cross-device/role tickets, expired values, malformed key
    /// material, and any signed-key substitution before an AEAD is derived.
    pub fn validate_for(&self, device_id: &str, role: &str, now_ms: u64) -> Result<(), String> {
        if self.v != 1
            || !valid_id(&self.jti)
            || !valid_id(&self.session_nonce)
            || !valid_id(&self.transfer_id)
            || !valid_id(&self.tenant_id)
            || !valid_id(&self.principal_id)
            || !valid_id(&self.source_device_id)
            || !valid_id(&self.destination_device_id)
            || !valid_id(&self.source_workspace_id)
            || !valid_id(&self.destination_workspace_id)
            || !valid_hex(&self.plan_sha256, 32)
            || role != self.role
            || device_id != self.device_id
            || self.exp <= now_ms
            || self.max_bytes == 0
            || self.epoch == 0
            || self.fence == 0
            || !matches!(role, "source" | "destination")
            || device_id
                != if role == "source" {
                    &self.source_device_id
                } else {
                    &self.destination_device_id
                }
            || !valid_hex(&self.source_device_public_key, 32)
            || !valid_hex(&self.destination_device_public_key, 32)
            || !valid_hex(&self.source_ephemeral_public_key, 32)
            || !valid_hex(&self.destination_ephemeral_public_key, 32)
            || !valid_hex(&self.source_ephemeral_signature, 64)
            || !valid_hex(&self.destination_ephemeral_signature, 64)
        {
            return Err("invalid transfer ticket binding".into());
        }
        self.verify_ephemeral_proofs()
    }

    pub fn verify_ephemeral_proofs(&self) -> Result<(), String> {
        verify_from_public_key_hex(
            &self.source_device_public_key,
            &self.ephemeral_proof("source")?,
            &self.source_ephemeral_signature,
        )
        .map_err(|_| "invalid source ephemeral proof".to_owned())?;
        verify_from_public_key_hex(
            &self.destination_device_public_key,
            &self.ephemeral_proof("destination")?,
            &self.destination_ephemeral_signature,
        )
        .map_err(|_| "invalid destination ephemeral proof".to_owned())
    }

    pub fn binding(&self) -> TransferCryptoBinding {
        TransferCryptoBinding {
            transfer_id: self.transfer_id.clone(),
            tenant_id: self.tenant_id.clone(),
            source_device_id: self.source_device_id.clone(),
            destination_device_id: self.destination_device_id.clone(),
            source_workspace_id: self.source_workspace_id.clone(),
            destination_workspace_id: self.destination_workspace_id.clone(),
            plan_sha256: self.plan_sha256.clone(),
            epoch: self.epoch,
            fence: self.fence,
            session_nonce: self.session_nonce.clone(),
        }
    }

    pub fn peer_ephemeral_public_key(&self, role: &str) -> Result<[u8; 32], String> {
        let raw = if role == "source" {
            &self.destination_ephemeral_public_key
        } else if role == "destination" {
            &self.source_ephemeral_public_key
        } else {
            return Err("invalid transfer role".into());
        };
        let bytes = decode_hex(raw)?;
        let mut out = [0_u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    fn ephemeral_proof(&self, role: &str) -> Result<Vec<u8>, String> {
        let (device, workspace, ephemeral) = match role {
            "source" => (
                &self.source_device_id,
                &self.source_workspace_id,
                &self.source_ephemeral_public_key,
            ),
            "destination" => (
                &self.destination_device_id,
                &self.destination_workspace_id,
                &self.destination_ephemeral_public_key,
            ),
            _ => return Err("invalid transfer role".into()),
        };
        let plan = decode_hex(&self.plan_sha256)?;
        let ephemeral = decode_hex(ephemeral)?;
        if plan.len() != 32 || ephemeral.len() != 32 {
            return Err("invalid transfer proof key material".into());
        }
        let mut out = Vec::new();
        push_proof_string(&mut out, EPHEMERAL_PROOF_DOMAIN)?;
        push_proof_string(&mut out, &self.transfer_id)?;
        push_proof_string(&mut out, &self.tenant_id)?;
        out.push(if role == "source" { 1 } else { 2 });
        push_proof_string(&mut out, device)?;
        push_proof_string(&mut out, workspace)?;
        out.extend_from_slice(&plan);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.fence.to_be_bytes());
        push_proof_string(&mut out, &self.session_nonce)?;
        out.extend_from_slice(&ephemeral);
        out.extend_from_slice(&self.exp.to_be_bytes());
        Ok(out)
    }
}

fn push_proof_string(out: &mut Vec<u8>, value: &str) -> Result<(), String> {
    let length = u32::try_from(value.len()).map_err(|_| "transfer proof field too long")?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

#[derive(Clone)]
pub struct TransferCryptoBinding {
    pub transfer_id: String,
    pub tenant_id: String,
    pub source_device_id: String,
    pub destination_device_id: String,
    pub source_workspace_id: String,
    pub destination_workspace_id: String,
    pub plan_sha256: String,
    pub epoch: u32,
    pub fence: u64,
    pub session_nonce: String,
}

impl TransferCryptoBinding {
    fn canonical(&self) -> Result<Vec<u8>, String> {
        let fields = [
            &self.transfer_id,
            &self.tenant_id,
            &self.source_device_id,
            &self.destination_device_id,
            &self.source_workspace_id,
            &self.destination_workspace_id,
            &self.plan_sha256,
            &self.session_nonce,
        ];
        if fields
            .iter()
            .any(|v| v.is_empty() || v.len() > 256 || v.bytes().any(|b| b.is_ascii_control()))
            || self.epoch == 0
            || self.fence == 0
            || self.plan_sha256.len() != 64
            || !self.plan_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("invalid transfer crypto binding".into());
        }
        let mut out = Vec::from(DOMAIN);
        for field in fields {
            out.extend_from_slice(&(field.len() as u32).to_be_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.fence.to_be_bytes());
        Ok(out)
    }
    fn nonce(&self, sequence: u64) -> [u8; 12] {
        let mut nonce = [0_u8; 12];
        nonce[..4].copy_from_slice(&self.epoch.to_be_bytes());
        nonce[4..].copy_from_slice(&sequence.to_be_bytes());
        nonce
    }
}

pub struct TransferEphemeral {
    private: Option<agreement::EphemeralPrivateKey>,
    public: [u8; 32],
}

impl TransferEphemeral {
    pub fn generate() -> Result<Self, String> {
        let rng = rand::SystemRandom::new();
        let private = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
            .map_err(|_| "generate x25519 key")?;
        let public = private
            .compute_public_key()
            .map_err(|_| "derive x25519 public key")?;
        let mut bytes = [0_u8; 32];
        if public.as_ref().len() != bytes.len() {
            return Err("unexpected x25519 public key length".into());
        }
        bytes.copy_from_slice(public.as_ref());
        Ok(Self {
            private: Some(private),
            public: bytes,
        })
    }
    pub const fn public(&self) -> &[u8; 32] {
        &self.public
    }
    pub fn derive(
        mut self,
        peer_public: &[u8],
        binding: &TransferCryptoBinding,
    ) -> Result<TransferCipher, String> {
        if peer_public.len() != 32 {
            return Err("invalid peer x25519 public key".into());
        }
        let private = self
            .private
            .take()
            .ok_or("ephemeral key already consumed")?;
        let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, peer_public);
        let info = binding.canonical()?;
        let key = agreement::agree_ephemeral(private, &peer, |shared| {
            // Keep the X25519 shared secret in ring's short-lived agreement
            // buffer: it is never copied into a heap allocation or serialized.
            let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, binding.plan_sha256.as_bytes());
            let prk = salt.extract(shared);
            let info_parts = [DOMAIN, info.as_slice()];
            let okm = prk
                .expand(&info_parts, AesKeyLen)
                .map_err(|_| "hkdf expand failed".to_owned())?;
            let mut key = [0_u8; 32];
            okm.fill(&mut key)
                .map_err(|_| "hkdf fill failed".to_owned())?;
            let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, &key)
                .map_err(|_| "aes key failed".to_owned());
            key.fill(0);
            unbound.map(aead::LessSafeKey::new)
        })
        .map_err(|_| "x25519 agreement failed".to_owned())??;
        Ok(TransferCipher {
            key,
            binding: binding.clone(),
        })
    }
}
struct AesKeyLen;
impl hkdf::KeyType for AesKeyLen {
    fn len(&self) -> usize {
        32
    }
}

pub struct TransferCipher {
    key: aead::LessSafeKey,
    binding: TransferCryptoBinding,
}
impl TransferCipher {
    pub fn seal(
        &self,
        sequence: u64,
        offset: u64,
        chunk_sha256: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, String> {
        if plaintext.is_empty() || plaintext.len() > 64 * 1024 {
            return Err("invalid transfer plaintext length".into());
        }
        let ad = additional_data(
            &self.binding,
            sequence,
            offset,
            plaintext.len(),
            chunk_sha256,
        )?;
        let nonce = aead::Nonce::assume_unique_for_key(self.binding.nonce(sequence));
        let mut out = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, aead::Aad::from(ad.as_slice()), &mut out)
            .map_err(|_| "aes seal failed")?;
        Ok(out)
    }
    pub fn open(
        &self,
        sequence: u64,
        offset: u64,
        length: usize,
        chunk_sha256: &str,
        ciphertext: &mut [u8],
    ) -> Result<Vec<u8>, String> {
        if length == 0 || length > 64 * 1024 || ciphertext.len() != length + 16 {
            return Err("invalid transfer ciphertext length".into());
        }
        let ad = additional_data(&self.binding, sequence, offset, length, chunk_sha256)?;
        let nonce = aead::Nonce::assume_unique_for_key(self.binding.nonce(sequence));
        let plain = self
            .key
            .open_in_place(nonce, aead::Aad::from(ad.as_slice()), ciphertext)
            .map_err(|_| "aes open failed")?;
        if sha_hex(plain) != chunk_sha256 {
            return Err("transfer chunk hash mismatch".into());
        }
        Ok(plain.to_vec())
    }
}
fn additional_data(
    binding: &TransferCryptoBinding,
    sequence: u64,
    offset: u64,
    length: usize,
    chunk_sha256: &str,
) -> Result<Vec<u8>, String> {
    if chunk_sha256.len() != 64 || !chunk_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid chunk hash".into());
    }
    let mut ad = binding.canonical()?;
    ad.extend_from_slice(&sequence.to_be_bytes());
    ad.extend_from_slice(&offset.to_be_bytes());
    ad.extend_from_slice(&(length as u64).to_be_bytes());
    ad.extend_from_slice(chunk_sha256.as_bytes());
    Ok(ad)
}
fn sha_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 15) as usize] as char);
    }
    out
}

fn valid_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes.saturating_mul(2)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("invalid hexadecimal value".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| "invalid hexadecimal value".to_owned())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ownmesh_identity::DeviceKeyPair;
    fn binding() -> TransferCryptoBinding {
        TransferCryptoBinding {
            transfer_id: "xfer_1".into(),
            tenant_id: "ten_1".into(),
            source_device_id: "dev_s".into(),
            destination_device_id: "dev_d".into(),
            source_workspace_id: "ws_s".into(),
            destination_workspace_id: "ws_d".into(),
            plan_sha256: "a".repeat(64),
            epoch: 1,
            fence: 1,
            session_nonce: "nonce_1".into(),
        }
    }
    #[test]
    fn x25519_hkdf_aes_binds_every_chunk_fact() {
        let a = TransferEphemeral::generate().unwrap();
        let b = TransferEphemeral::generate().unwrap();
        let ap = *a.public();
        let bp = *b.public();
        let bind = binding();
        let sender = a.derive(&bp, &bind).unwrap();
        let receiver = b.derive(&ap, &bind).unwrap();
        let body = b"abc";
        let hash = sha_hex(body);
        let mut enc = sender.seal(0, 0, &hash, body).unwrap();
        assert_eq!(receiver.open(0, 0, 3, &hash, &mut enc).unwrap(), body);
        assert!(receiver.open(1, 0, 3, &hash, &mut enc).is_err());
    }

    fn hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 15) as usize] as char);
        }
        out
    }

    fn signed_ticket() -> AgentTransferTicket {
        let source = DeviceKeyPair::generate();
        let destination = DeviceKeyPair::generate();
        let source_ephemeral = TransferEphemeral::generate().unwrap();
        let destination_ephemeral = TransferEphemeral::generate().unwrap();
        let mut ticket = AgentTransferTicket {
            v: 1,
            jti: "jti_1".into(),
            session_nonce: "session_1".into(),
            transfer_id: "xfer_1".into(),
            tenant_id: "ten_1".into(),
            principal_id: "prin_1".into(),
            device_id: "dev_s".into(),
            role: "source".into(),
            source_device_id: "dev_s".into(),
            destination_device_id: "dev_d".into(),
            source_workspace_id: "ws_s".into(),
            destination_workspace_id: "ws_d".into(),
            plan_sha256: "a".repeat(64),
            epoch: 1,
            fence: 1,
            max_bytes: 64 * 1024,
            exp: u64::MAX,
            source_device_public_key: source.public_identity().public_key_hex,
            destination_device_public_key: destination.public_identity().public_key_hex,
            source_ephemeral_public_key: hex(source_ephemeral.public()),
            destination_ephemeral_public_key: hex(destination_ephemeral.public()),
            source_ephemeral_signature: String::new(),
            destination_ephemeral_signature: String::new(),
        };
        ticket.source_ephemeral_signature = hex(source
            .sign(&ticket.ephemeral_proof("source").unwrap())
            .expose());
        ticket.destination_ephemeral_signature = hex(destination
            .sign(&ticket.ephemeral_proof("destination").unwrap())
            .expose());
        ticket
    }

    #[test]
    fn ticket_rejects_key_swap_role_and_signed_fact_substitution() {
        let ticket = signed_ticket();
        ticket.validate_for("dev_s", "source", 1).unwrap();
        assert_eq!(
            ticket.peer_ephemeral_public_key("source").unwrap().len(),
            32
        );
        assert!(ticket.validate_for("dev_d", "source", 1).is_err());
        let mut swapped = signed_ticket();
        swapped.destination_ephemeral_public_key = "ff".repeat(32);
        assert!(swapped.validate_for("dev_s", "source", 1).is_err());
        let mut replay = signed_ticket();
        replay.epoch = 2;
        assert!(replay.validate_for("dev_s", "source", 1).is_err());
    }

    #[test]
    fn ephemeral_proof_golden_vector_is_unambiguous_for_delimiter_ids() {
        let mut ticket = signed_ticket();
        ticket.transfer_id = "x|=fer".into();
        ticket.tenant_id = "t=|".into();
        ticket.source_device_id = "dev|=".into();
        ticket.source_workspace_id = "ws=|".into();
        ticket.plan_sha256 = "00".repeat(32);
        ticket.source_ephemeral_public_key = "11".repeat(32);
        ticket.epoch = 0x0102_0304;
        ticket.fence = 0x0102_0304_0506;
        ticket.session_nonce = "n|=".into();
        ticket.exp = 1_700_000_000_000;
        let proof = ticket.ephemeral_proof("source").unwrap();
        let mut different = ticket;
        different.transfer_id = "x".into();
        different.tenant_id = "=fer|t=|".into();
        assert_ne!(proof, different.ephemeral_proof("source").unwrap());
    }
}
