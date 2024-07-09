use cairovm_verifier_stark::types::StarkProof;
use starknet_crypto::Felt;

const SECURITY_BITS: Felt = Felt::from_hex_unchecked("0x32");

#[no_mangle]
pub unsafe extern "C" fn verify_cairo_vm_proof_ffi(
    proof_bytes: *const u8,
    proof_len: u32,
    program_hash: *const u8,
    program_hash_len: u32,
) -> bool {
    if proof_bytes.is_null() || program_hash.is_null() {
        return false;
    }

    let proof_bytes = unsafe { std::slice::from_raw_parts(proof_bytes, proof_len as usize) };

    let expected_program_hash =
        unsafe { std::slice::from_raw_parts(program_hash, program_hash_len as usize) };

    if let Ok(stark_proof) = bincode::deserialize::<StarkProof>(proof_bytes) {
        let verified_program_hash = stark_proof.verify(SECURITY_BITS).unwrap();
        assert_eq!(verified_program_hash.to_bytes_be(), expected_program_hash);
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    const PROOF: &[u8] =
        include_bytes!("../../../../scripts/test_files/cairo_vm/fibonacci_proof_generator/recursive/cairo0_example_proof.json");
    const PROGRAM_HASH: &[u8] = include_bytes!(
        "../../../../scripts/test_files/cairo_vm/fibonacci_proof_generator/cairo0_fibonacci.json"
    );

    #[test]
    fn verify_cairo_vm_proof_with_program_hash_works() {
        let proof_bytes = PROOF.as_ptr();
        let program_hash = PROGRAM_HASH.as_ptr();

        let result = unsafe {
            verify_cairo_vm_proof_ffi(
                proof_bytes,
                PROOF.len() as u32,
                program_hash,
                PROGRAM_HASH.len() as u32,
            )
        };
        assert!(result)
    }

    #[test]
    fn verify_cairo_vm_proof_with_bad_proof() {
        let proof_bytes = PROOF.as_ptr();
        let program_hash = PROGRAM_HASH.as_ptr();

        let result = unsafe {
            verify_cairo_vm_proof_ffi(
                proof_bytes,
                (PROOF.len() - 1) as u32,
                program_hash,
                PROGRAM_HASH.len() as u32,
            )
        };
        assert!(!result)
    }
}
