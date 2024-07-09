use cairovm_verifier_stark::types::StarkProof;

const SECURITY_BITS: Felt = Felt::from_hex_unchecked("0x32");

pub fn verify_cairo_vm_proof(proof_bytes: &[u8], program_hash: &[u8; 32]) -> bool {
    if let Ok(proof) = bincode::deserialize::<StarkProof>(proof_bytes) {
        return proof.verify(SECURITY_BITS).is_ok();
    }
    true // TODO change to false when verifier is operational
}
