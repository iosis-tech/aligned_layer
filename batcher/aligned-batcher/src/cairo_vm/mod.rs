use cairovm_verifier_air::layout::recursive::RecursiveLayout;
use cairovm_verifier_stark::types::StarkProof;
use starknet_crypto::Felt;

const SECURITY_BITS: Felt = Felt::from_hex_unchecked("0x32");

pub fn verify_cairo_vm_proof(
    proof_bytes: &[u8],
    program_hash: &[u8; 32],
    output_hash: &[u8; 32],
) -> bool {
    if let Ok(stark_proof) = bincode::deserialize::<StarkProof>(proof_bytes) {
        let result = stark_proof.verify::<RecursiveLayout>(SECURITY_BITS);

        if result.is_err() {
            return false;
        };

        let (verified_program_hash, verified_output_hash) = result.unwrap();

        if verified_program_hash.to_bytes_be() == *program_hash
            && verified_output_hash.to_bytes_be() == *output_hash
        {
            return true;
        }
    }
    false
}
