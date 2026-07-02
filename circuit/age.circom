// zk-age: Age verification circuit
//
// Proves that a person is at least `threshold` years old without revealing
// their actual birthdate.
//
// Signature scheme: Poseidon-based Schnorr-like signature
// - Issuer secret key: sk (random field element, known only to issuer)
// - Issuer public key: pk = Poseidon(sk) (public input)
// - Signature on message m: choose random r, compute h = Poseidon(pk, m, r),
//   then sig = sk + h
// - Verification: Poseidon(sig - h) === pk (since sig - h = sk)
//
// This is secure because forging a signature requires a preimage attack on
// Poseidon (assumed hard over the BN254 scalar field).
//
// Public inputs:  current_year, threshold, issuer_pubkey
// Private inputs: birth_year, issuer_signature, signature_nonce

pragma circom 2.2.3;

include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/poseidon.circom";

template AgeVerify() {
    // Public inputs
    signal input current_year;
    signal input threshold;
    signal input issuer_pubkey;       // pk = Poseidon(sk)

    // Private inputs
    signal input birth_year;          // message m
    signal input issuer_signature;    // sig = sk + h
    signal input signature_nonce;     // r (random nonce)

    // --- Constraint 1: Age check ---
    // age = current_year - birth_year
    // We need age >= threshold, i.e., current_year - birth_year >= threshold
    signal diff;
    diff <== current_year - threshold - birth_year;

    // Enforce diff >= 0 by requiring it fits in 16 bits
    component n2b = Num2Bits(16);
    n2b.in <== diff;

    // --- Constraint 2: Poseidon signature verification ---
    // h = Poseidon(pk, m, r) = Poseidon(issuer_pubkey, birth_year, signature_nonce)
    component hashChallenge = Poseidon(3);
    hashChallenge.inputs[0] <== issuer_pubkey;
    hashChallenge.inputs[1] <== birth_year;
    hashChallenge.inputs[2] <== signature_nonce;

    // sig - h = sk (recoverable only by issuer who knows sk)
    signal recovered_sk;
    recovered_sk <== issuer_signature - hashChallenge.out;

    // Poseidon(sk) === pk
    component hashPk = Poseidon(1);
    hashPk.inputs[0] <== recovered_sk;
    hashPk.out === issuer_pubkey;
}

component main { public [current_year, threshold, issuer_pubkey] } = AgeVerify();
