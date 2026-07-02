#!/bin/bash
# Build script for zk-age circuit with Poseidon signature
# Produces: age.wasm, age_final.zkey, verification_key.json
set -e

cd "$(dirname "$0")/../circuit"

echo "=== Installing circomlib ==="
npm install circomlib 2>/dev/null || true

echo "=== Compiling circuit ==="
circom age.circom --r1cs --wasm --sym -l node_modules

echo "=== Trusted setup (Powers of Tau) ==="
# Download the powers of tau ceremony file (already completed for circuits up to 2^22)
if [ ! -f powersOfTau28_hez_final_11.ptau ]; then
    curl -Ls https://github.com/iden3/snarkjs/releases/download/v0.7.4/powersOfTau28_hez_final_11.ptau -o powersOfTau28_hez_final_11.ptau
fi

echo "=== Groth16 setup ==="
# Generate the .zkey (proving key)
snarkjs groth16 setup age.r1cs powersOfTau28_hez_final_11.ptau age_0000.zkey

# Contribute to the ceremony (random beacon for demo)
snarkjs zkey contribute age_0000.zkey age_final.zkey --name="demo contribution" -v -e="random entropy for demo"

# Export verification key
snarkjs zkey export verificationkey age_final.zkey verification_key.json

echo "=== Copy artifacts to build/ ==="
mkdir -p ../build
cp -r age_js ../build/
cp age_final.zkey ../build/
cp verification_key.json ../build/

echo "=== Done! ==="
echo "Build artifacts in build/:"
ls -la ../build/
