// zk-age: Age verification circuit
//
// Proves that a person is at least `threshold` years old without revealing
// their actual birthdate.
//
// WARNING: The signature scheme in this circuit is a placeholder for demo
// purposes only. It is trivially forgeable and provides NO credential
// security. The next sprint replaces it with a Poseidon/Merkle-tree-based
// issuer registry. See README for the production upgrade path.
//
// Public inputs:  current_year, threshold, issuer_pubkey_hash
// Private inputs: birth_year, issuer_signature, signature_randomness

pragma circom 2.2.3;

include "node_modules/circomlib/circuits/comparators.circom";

template AgeVerify() {
    // Public inputs
    signal input current_year;
    signal input threshold;
    signal input issuer_pubkey_hash;

    // Private inputs
    signal input birth_year;
    signal input issuer_signature;
    signal input signature_randomness;

    // --- Constraint 1: Age check ---
    // age = current_year - birth_year
    // We need age >= threshold, i.e., current_year - birth_year >= threshold
    signal diff;
    diff <== current_year - threshold - birth_year;

    // Enforce diff >= 0 by requiring it fits in 16 bits
    component n2b = Num2Bits(16);
    n2b.in <== diff;

    // --- Constraint 2: Demo signature placeholder (NOT secure) ---
    // This is replaced by a real ZK-friendly signature in the next sprint.
    signal expected_sig;
    expected_sig <== birth_year + issuer_pubkey_hash * signature_randomness;
    expected_sig === issuer_signature;
}

component main { public [current_year, threshold, issuer_pubkey_hash] } = AgeVerify();
