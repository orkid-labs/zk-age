//! Issuer — represents a government ID authority that signs birthdate
//! commitments using a Poseidon-based Schnorr-like signature.
//!
//! Signature scheme:
//! - Issuer secret key: sk (random field element, known only to issuer)
//! - Issuer public key: pk = Poseidon(sk) (public input to circuit)
//! - To sign message m (birth_year):
//!   1. Choose random nonce r
//!   2. Compute challenge h = Poseidon(pk, m, r)
//!   3. Compute signature sig = sk + h (mod p)
//! - Circuit verifies: Poseidon(sig - h) === pk (since sig - h = sk)
//!
//! Security: forging requires a preimage attack on Poseidon over BN254.

use anyhow::Result;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use pso_poseidon::{Poseidon, PoseidonHasher};
use rand::Rng;

use crate::types::{IssueRequest, IssueResponse};

/// Issuer secret key (demo: hardcoded). In production this would be in an HSM
/// or generated via a secure key ceremony. The field element is the BN254
/// scalar field (modulus ~2^254).
const ISSUER_SK_HEX: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";

/// Parse a hex string into a BN254 Fr field element.
fn fr_from_hex(hex: &str) -> Fr {
    let bytes = hex.strip_prefix("0x").unwrap_or(hex);
    let big_int = num_bigint::BigUint::parse_bytes(bytes.as_bytes(), 16)
        .expect("invalid hex for field element");
    Fr::from_le_bytes_mod_order(&big_int.to_bytes_le())
}

/// Convert an Fr to a decimal string (for JSON serialization to circom).
fn fr_to_string(fr: &Fr) -> String {
    let big_int: num_bigint::BigUint = fr.into_bigint().into();
    big_int.to_str_radix(10)
}

/// Compute the issuer's public key: pk = Poseidon(sk).
fn issuer_pubkey() -> Fr {
    let sk = fr_from_hex(ISSUER_SK_HEX);
    let mut poseidon = Poseidon::<Fr>::new_circom(1).expect("failed to init Poseidon");
    poseidon.hash(&[sk]).expect("failed to hash sk")
}

/// Issue a Poseidon-based signature on the user's birth year.
///
/// Returns (issuer_pubkey, signature, nonce) — all as decimal strings
/// compatible with circom/snarkjs input format.
pub fn issue(req: &IssueRequest) -> Result<IssueResponse> {
    let sk = fr_from_hex(ISSUER_SK_HEX);
    let pk = issuer_pubkey();

    // Message = birth_year as field element
    let message = Fr::from(req.birth_year);

    // Random nonce
    let nonce_bytes: [u8; 32] = rand::thread_rng().gen();
    let nonce = Fr::from_le_bytes_mod_order(&nonce_bytes);

    // Challenge: h = Poseidon(pk, m, r)
    let mut poseidon3 = Poseidon::<Fr>::new_circom(3).expect("failed to init Poseidon(3)");
    let h = poseidon3
        .hash(&[pk, message, nonce])
        .expect("failed to compute challenge hash");

    // Signature: sig = sk + h (mod p)
    let sig = sk + h;

    Ok(IssueResponse {
        issuer_pubkey: fr_to_string(&pk),
        issuer_signature: fr_to_string(&sig),
        signature_nonce: fr_to_string(&nonce),
        birth_year: req.birth_year,
    })
}
