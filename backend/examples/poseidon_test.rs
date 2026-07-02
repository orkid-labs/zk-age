use ark_bn254::Fr;
use ark_ff::PrimeField;
use pso_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;

fn fr_from_hex(hex: &str) -> Fr {
    let bytes = hex.strip_prefix("0x").unwrap_or(hex);
    let big_int = BigUint::parse_bytes(bytes.as_bytes(), 16).expect("invalid hex");
    Fr::from_le_bytes_mod_order(&big_int.to_bytes_le())
}

fn fr_to_string(fr: &Fr) -> String {
    let big_int: BigUint = fr.into_bigint().into();
    big_int.to_str_radix(10)
}

fn main() {
    let sk = fr_from_hex("0x0000000000000000000000000000000000000000000000000000000000000001");
    
    // Compute pk = Poseidon(sk)
    let mut poseidon1 = Poseidon::<Fr>::new_circom(1).expect("failed to init Poseidon(1)");
    let pk = poseidon1.hash(&[sk]).expect("failed to hash sk");
    
    println!("Issuer public key (decimal): {}", fr_to_string(&pk));
    
    // Simulate signing birth_year=2000
    let message = Fr::from(2000u64);
    
    // Random nonce
    let nonce = Fr::from(12345u64);
    
    // h = Poseidon(pk, m, r)
    let mut poseidon3 = Poseidon::<Fr>::new_circom(3).expect("failed to init Poseidon(3)");
    let h = poseidon3.hash(&[pk, message, nonce]).expect("failed to compute challenge");
    
    // sig = sk + h
    let sig = sk + h;
    
    println!("Message (birth_year): 2000");
    println!("Nonce (decimal): {}", fr_to_string(&nonce));
    println!("Challenge h (decimal): {}", fr_to_string(&h));
    println!("Signature (decimal): {}", fr_to_string(&sig));
    
    // Verify: Poseidon(sig - h) === pk
    let recovered_sk = sig - h;
    let computed_pk = poseidon1.hash(&[recovered_sk]).expect("failed to verify");
    println!("Verification: Poseidon(sig-h) === pk? {}", computed_pk == pk);
    
    // Output circom input JSON
    let current_year = 2026u64;
    let threshold = 18u64;
    println!("\n=== Circom input JSON ===");
    println!("{{");
    println!("  \"current_year\": \"{}\",", current_year);
    println!("  \"threshold\": \"{}\",", threshold);
    println!("  \"issuer_pubkey\": \"{}\",", fr_to_string(&pk));
    println!("  \"birth_year\": \"{}\",", 2000);
    println!("  \"issuer_signature\": \"{}\",", fr_to_string(&sig));
    println!("  \"signature_nonce\": \"{}\"", fr_to_string(&nonce));
    println!("}}");
}
