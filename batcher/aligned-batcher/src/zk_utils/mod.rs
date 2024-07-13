use log::{debug, warn};

use aligned_sdk::types::{ProvingSystemId, VerificationData};

use crate::cairo_vm::verify_cairo_vm_proof;
use crate::gnark::verify_gnark;
use crate::risc_zero::verify_risc_zero_proof;
use crate::sp1::verify_sp1_proof;

pub(crate) fn verify(verification_data: &VerificationData) -> bool {
    match verification_data.proving_system {
        ProvingSystemId::SP1 => {
            if let Some(elf) = &verification_data.vm_program_code {
                return verify_sp1_proof(verification_data.proof.as_slice(), elf.as_slice());
            }
            warn!("Trying to verify SP1 proof but ELF was not provided. Returning false");
            false
        }
        ProvingSystemId::Risc0 => {
            if let (Some(image_id_slice), Some(pub_input)) = (
                &verification_data.vm_program_code,
                &verification_data.pub_input,
            ) {
                let mut image_id = [0u8; 32];
                image_id.copy_from_slice(image_id_slice.as_slice());
                return verify_risc_zero_proof(
                    verification_data.proof.as_slice(),
                    &image_id,
                    pub_input,
                );
            }

            warn!("Trying to verify Risc0 proof but image id or public input was not provided. Returning false");
            false
        }
        ProvingSystemId::Cairo => {
            if let (Some(vm_program_code), proof, Some(pub_input)) = (
                &verification_data.vm_program_code,
                &verification_data.proof,
                &verification_data.pub_input,
            ) {
                let mut program_hash = [0u8; 32];
                program_hash.copy_from_slice(vm_program_code.as_slice());
                let mut public_input = [0u8; 32];
                public_input.copy_from_slice(pub_input.as_slice());
                return verify_cairo_vm_proof(proof.as_slice(), &program_hash, &public_input);
            }
            warn!("Trying to verify Cairo VM Proof. Returning false");
            false
        }
        ProvingSystemId::GnarkPlonkBls12_381
        | ProvingSystemId::GnarkPlonkBn254
        | ProvingSystemId::Groth16Bn254 => {
            let vk = verification_data
                .verification_key
                .as_ref()
                .expect("Verification key is required");

            let pub_input = verification_data
                .pub_input
                .as_ref()
                .expect("Public input is required");
            let is_valid = verify_gnark(
                &verification_data.proving_system,
                &verification_data.proof,
                pub_input,
                vk,
            );
            debug!("Gnark proof is valid: {}", is_valid);
            is_valid
        }
        ProvingSystemId::Halo2KZG => todo!(),
        ProvingSystemId::Halo2IPA => todo!(),
    }
}
