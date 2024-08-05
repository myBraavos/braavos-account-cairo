use core::starknet::SyscallResultTrait;
use core::result::ResultTrait;
use core::clone::Clone;
use array::{ArrayTrait, SpanTrait};
use ecdsa::check_ecdsa_signature;
use option::{OptionTrait};
use serde::Serde;
use starknet::{library_call_syscall, ContractAddress, call_contract_syscall};
use starknet::secp256_trait::{Secp256PointTrait, Signature, is_valid_signature};
use starknet::secp256r1::{Secp256r1Impl, Secp256r1Point, Secp256r1PointImpl};
use traits::{Into, TryInto};

use braavos_account::utils::hash::sha256_u32;
use super::super::utils::utils::{
    u32_shr_div_for_pos, reconstruct_hash_from_challenge, concat_u32_with_padding, IntoOrPanic
};
use super::signer_management::{SignerType,};
use super::signer_address_mgt::{exists, add_signer};

#[derive(Copy, Drop, Serde, starknet::Store)]
struct StarkPubKey {
    pub_key: felt252
}

#[generate_trait]
impl StarkSignerMethods of StarkSignerMethodsTrait {
    /// Returns true if given signature is valid
    fn validate_signature(self: @StarkPubKey, hash: felt252, signature: Span<felt252>) -> bool {
        check_ecdsa_signature(hash, *self.pub_key, *signature.at(0), *signature.at(1))
    }

    /// Returns a single felt representation of the signer. In this case it is just the pub key
    fn guid(self: @StarkPubKey) -> felt252 {
        *self.pub_key
    }

    fn exists(self: @StarkPubKey) -> Option<felt252> {
        let guid: felt252 = self.guid();
        let guid_exists = exists(SignerType::Stark, guid);
        if guid_exists {
            Option::Some(guid)
        } else {
            Option::None
        }
    }

    /// Adds this signer pub key to the account storage
    fn add_signer(self: @StarkPubKey) {
        add_signer(SignerType::Stark, self.guid());
    }
}

const SHA256_CAIRO_0_LIB: felt252 =
    0x4dacc042b398d6f385a87e7dd65d2bcb3270bb71c4b34857b3c658c7f52cf6d;
const SHA256_CAIRO_0_SELECTOR: felt252 = selector!("sha256_cairo0");

#[derive(Copy, Drop, Serde, starknet::Store)]
struct Secp256r1PubKey {
    pub_x: u256,
    pub_y: u256
}


#[generate_trait]
impl Secp256r1SignerMethods of Secp256r1SignerMethodsTrait {
    /// Returns true if given signature is valid
    fn validate_signature(self: @Secp256r1PubKey, hash: felt252, signature: Span<felt252>) -> bool {
        let hash_u256: u256 = hash.into();
        let sig = Signature {
            r: u256 {
                low: (*signature.at(0)).try_into().unwrap(),
                high: (*signature.at(1)).try_into().unwrap()
            },
            s: u256 {
                low: (*signature.at(2)).try_into().unwrap(),
                high: (*signature.at(3)).try_into().unwrap()
            },
            y_parity: false,
        };
        is_valid_signature::<
            Secp256r1Point
        >(
            hash_u256,
            sig.r,
            sig.s,
            Secp256r1Impl::secp256_ec_new_syscall(*self.pub_x, *self.pub_y)
                .unwrap_syscall()
                .unwrap()
        )
    }

    /// Returns true if the given signature is a valid webauthn signature
    /// Signature contains all required payload including client data and auth data
    fn validate_webauthn_signature(
        self: @Secp256r1PubKey, hash: felt252, signature: Span<felt252>
    ) -> bool {
        let mut offset = 0;
        let auth_data_len = (*signature.at(offset)).try_into().unwrap();
        let auth_data = signature.slice(offset + 1, auth_data_len);
        let auth_data_flag: u32 = (*auth_data.at(8)).try_into().unwrap();
        assert((auth_data_flag & 0x05000000) == 0x05000000, 'INVALID_AUTH_DATA_FLAGS');
        offset += auth_data_len + 1;
        let auth_data_u32s_padding: u32 = (*signature.at(offset)).try_into().unwrap();
        assert(auth_data_u32s_padding < 4, 'INVALID_PADDING');
        offset += 1;
        let cdata_offset = offset + 1;
        let client_data_len = (*signature.at(offset)).try_into().unwrap();
        let client_data = signature.slice(cdata_offset, client_data_len);
        offset += 1 + client_data_len;
        let client_data_u32s_padding: u32 = (*signature.at(offset)).try_into().unwrap();
        assert(client_data_u32s_padding < 4, 'INVALID_PADDING');
        offset += 1;
        let challenge_offset: u32 = (*signature.at(offset)).try_into().unwrap();
        let challenge_len: u32 = (*signature.at(offset + 1)).try_into().unwrap();
        let challenge_offset_u32 = challenge_offset / 4;
        let challenge_offset_u32_rem = challenge_offset % 4;
        let challenge_end_offset_u32 = (challenge_offset + challenge_len) / 4;
        let challenge_end_offset_u32_rem = (challenge_offset + challenge_len) % 4;
        // At most 256 bit challenge, split into 6 bit chunks for base64 encoding
        assert(challenge_len <= 43, 'INVALID_CHALLENGE_LEN');
        assert(
            challenge_offset
                + challenge_len < ((cdata_offset + client_data_len) * 4 - client_data_u32s_padding),
            'INVALID_CHALLENGE_OFFSET'
        );
        // Assert that the challenge is enclosed in double quotes
        let char_before_offset = challenge_offset_u32
            - if challenge_offset_u32_rem == 0 {
                1
            } else {
                0
            };
        let char_before_rem = if challenge_offset_u32_rem == 0 {
            3
        } else {
            challenge_offset_u32_rem - 1
        };
        let char_before_div = u32_shr_div_for_pos(char_before_rem);
        let char_before = (*signature.at(cdata_offset + char_before_offset)).try_into().unwrap()
            / char_before_div & 0xFF;
        assert(char_before == 0x22, 'INVALID_CHALLENGE_OFFSET');
        let char_after_div = u32_shr_div_for_pos(challenge_end_offset_u32_rem);
        let char_after = (*signature.at(cdata_offset + challenge_end_offset_u32))
            .try_into()
            .unwrap()
            / char_after_div & 0xFF;
        assert(char_after == 0x22, 'INVALID_CHALLENGE_OFFSET');

        // Assert that decoded challenge corresponds to transaction hash
        let base64_padding: u8 = (*signature.at(offset + 2)).try_into().unwrap();
        // challange hash is byte aligned so only 2**P where P E { 8n mod 6 | n E N} are valid
        assert(
            base64_padding == 0 || base64_padding == 4 || base64_padding == 16, 'INVALID_PADDING'
        );
        let challenge_len_with_rem = challenge_end_offset_u32 - challenge_offset_u32 + 1;
        let mut challenge_with_rem = signature
            .slice(cdata_offset + challenge_offset_u32, challenge_len_with_rem);

        let reconstructed_hash = reconstruct_hash_from_challenge(
            ref challenge_with_rem, challenge_offset_u32_rem, challenge_len, base64_padding
        );
        assert(hash == reconstructed_hash, 'RECONSTRUCTED_HASH_MISMATCH');
        offset += 3;

        // Compute webauthn hash sha256(auth_data | sha256(client_data))
        let sig_rs = signature.slice(offset, 4);
        let mut webauthn_hash: u256 = 0;
        let mut force_cairo_impl: bool = signature.at(offset + 4) != @0;
        if !force_cairo_impl {
            let mut calldata: Array<felt252> = ArrayTrait::new();
            client_data.serialize(ref calldata);
            calldata.append((client_data.len() * 4 - client_data_u32s_padding).into());
            let cairo0_cdata_sha256_res = library_call_syscall(
                SHA256_CAIRO_0_LIB.try_into().unwrap(), SHA256_CAIRO_0_SELECTOR, calldata.span()
            );
            if cairo0_cdata_sha256_res.is_ok() {
                let mut cairo0_cdata_sha256 = cairo0_cdata_sha256_res.unwrap();
                cairo0_cdata_sha256.pop_front().expect('MISSING_LEN'); // first elem is len
                let auth_data_cdata_concat = concat_u32_with_padding(
                    auth_data, ref cairo0_cdata_sha256, auth_data_u32s_padding
                );
                calldata = array![];
                auth_data_cdata_concat.serialize(ref calldata);
                calldata.append((auth_data_cdata_concat.len() * 4 - auth_data_u32s_padding).into());
                // sha256(authdata || sha256(cdata))
                let cairo0_webauthn_hash = library_call_syscall(
                    SHA256_CAIRO_0_LIB.try_into().unwrap(),
                    SHA256_CAIRO_0_SELECTOR,
                    calldata.span(),
                )
                    .unwrap();

                webauthn_hash = cairo0_webauthn_hash
                    .slice(1, cairo0_webauthn_hash.len() - 1)
                    .into_or_panic();
            } else {
                force_cairo_impl = true;
            }
        }

        // force_cairo_impl is either sent from client or is set due to Cairo 0 failure which
        // can happen on regenesis or invalid input (that will fail on Cairo impl as well)
        if force_cairo_impl {
            let mut cdata_u32s: Array<u32> = client_data.into_or_panic();
            let mut cdata_hash = sha256_u32(cdata_u32s, client_data_u32s_padding);

            let auth_data_cdata_concat = concat_u32_with_padding(
                auth_data, ref cdata_hash, auth_data_u32s_padding
            );
            webauthn_hash =
                sha256_u32(auth_data_cdata_concat.span().into_or_panic(), auth_data_u32s_padding)
                .into_or_panic();
        }

        // Verify sig matches webauthn hash
        let sig = Signature {
            r: u256 {
                low: (*sig_rs.at(0)).try_into().unwrap(), high: (*sig_rs.at(1)).try_into().unwrap()
            },
            s: u256 {
                low: (*sig_rs.at(2)).try_into().unwrap(), high: (*sig_rs.at(3)).try_into().unwrap()
            },
            y_parity: false,
        };
        is_valid_signature::<
            Secp256r1Point
        >(
            webauthn_hash,
            sig.r,
            sig.s,
            Secp256r1Impl::secp256_ec_new_syscall(*self.pub_x, *self.pub_y)
                .unwrap_syscall()
                .unwrap()
        )
    }

    /// Returns true if secp256r1 pub key point is valid
    fn assert_valid_point(self: @Secp256r1PubKey) -> bool {
        self.pub_x != @0_u256
            && self.pub_y != @0_u256
            && Secp256r1Impl::secp256_ec_new_syscall(*self.pub_x, *self.pub_y)
                .unwrap_syscall()
                .is_some()
    }

    /// Returns a single felt representation of this signer. In this case it is the poseidon hash
    /// of the public key
    fn guid(self: @Secp256r1PubKey) -> felt252 {
        let mut serialized = ArrayTrait::new();
        self.serialize(ref serialized);
        poseidon::poseidon_hash_span(serialized.span())
    }

    /// Returns true if current signer is in the account storage
    fn exists(self: @Secp256r1PubKey, signer_type: SignerType) -> Option<felt252> {
        let mut guid_exists = false;
        let guid = self.guid();
        if signer_type == SignerType::Secp256r1 {
            guid_exists = exists(SignerType::Secp256r1, guid);
        } else if signer_type == SignerType::Webauthn {
            guid_exists = exists(SignerType::Webauthn, guid);
        }

        if guid_exists {
            Option::Some(guid)
        } else {
            Option::None
        }
    }

    /// Adds this signer pub key to the account storage
    fn add_signer(self: @Secp256r1PubKey, signer_type: SignerType) {
        if signer_type == SignerType::Secp256r1 {
            add_signer(SignerType::Secp256r1, self.guid(),);
        } else if signer_type == SignerType::Webauthn {
            add_signer(SignerType::Webauthn, self.guid(),);
        }
    }
}

#[derive(Copy, Drop, Serde, starknet::Store)]
struct MoaSigner {
    address: ContractAddress,
    pub_key: felt252,
}

#[derive(Copy, Drop, Serde)]
struct MoaExtSigner {
    signature_type: u128, // for future use
    signer: MoaSigner,
    preamble_r: felt252,
    preamble_s: felt252,
    ext_sig: Span<felt252>
}

impl MoaExtSignerIntoFelt252 of Into<MoaExtSigner, felt252> {
    fn into(self: MoaExtSigner) -> felt252 {
        self.signer.guid()
    }
}

#[generate_trait]
impl MoaExtSignerHelperMethods of MoaExtSignerHelperMethodsTrait {
    /// @param signature The signature of the transaction
    /// Format of a signature: [ A_type, A_address, A_pub_key, A_r, A_s, A_sig_len, A_ext_sig,
    /// ...etc]
    /// The parsing here allows duplicates. They are filtered later.
    /// @return The list of signers from the transaction signature
    fn resolve_signers_from_sig(signature: Span<felt252>) -> Array::<MoaExtSigner> {
        let mut signers = ArrayTrait::<MoaExtSigner>::new();

        let mut i = 0;
        loop {
            if (i >= signature.len()) {
                break;
            }
            let signature_type: u128 = (*signature.at(i)).try_into().unwrap();
            assert(signature_type == 0, 'INVALID_SIG_TYPE');
            let sig_len: usize = (*signature.at(i + 5)).try_into().unwrap();
            assert(sig_len > 0, 'INVALID_SIG');
            let inner_signer = MoaSigner {
                address: (*signature.at(i + 1)).try_into().unwrap(), pub_key: *signature.at(i + 2),
            };
            signers
                .append(
                    MoaExtSigner {
                        signature_type,
                        signer: inner_signer,
                        preamble_r: *signature.at(i + 3),
                        preamble_s: *signature.at(i + 4),
                        ext_sig: signature.slice(i + 6, sig_len)
                    }
                );
            i += 6 + sig_len;
        };
        assert(signers.len() > 0, 'INVALID_SIG');
        signers
    }

    fn get_signers_guids(mut signers: Span<MoaExtSigner>) -> Array<felt252> {
        let mut guids: Array<felt252> = ArrayTrait::new();

        loop {
            match signers.pop_front() {
                Option::Some(signer) => { guids.append(signer.signer.guid()); },
                Option::None(_) => { break (); },
            };
        };

        guids
    }
}

mod MoaConsts {
    const IS_VALID_SIGNATURE_FUNCTION_SELECTOR: felt252 = selector!("is_valid_signature");
}

#[generate_trait]
impl MoaSignerMethods of MoaSignerMethodsTrait {
    /// Returns true if given signature is valid
    fn validate_signature(
        self: @MoaSigner, hash: felt252, preamble_r: felt252, preamble_s: felt252
    ) -> bool {
        check_ecdsa_signature(hash, *self.pub_key, preamble_r, preamble_s)
    }


    /// @param hash The transaction hash
    /// @param sig The external signature
    ///
    /// Panic if external signature verification result is not VALIDATED
    fn assert_external_signature(self: @MoaSigner, hash: felt252, sig: Span<felt252>) {
        let mut calldata = ArrayTrait::<felt252>::new();
        calldata.append(hash);
        sig.serialize(ref calldata);

        let res = call_contract_syscall(
            *self.address, MoaConsts::IS_VALID_SIGNATURE_FUNCTION_SELECTOR, calldata.span()
        )
            .unwrap_syscall();

        assert(res.len() == 1, 'INVALID_SIG_RESULT_LENGTH');
        assert(
            *res.at(0) == 1 || *res.at(0) == starknet::VALIDATED, 'INVALID_SIG_VERIFICATION_RESULT'
        );
    }

    /// Returns a single felt representation of the signer. In this case it is the address and
    /// public key
    fn guid(self: @MoaSigner) -> felt252 {
        let mut serialized = ArrayTrait::new();
        self.serialize(ref serialized);
        poseidon::poseidon_hash_span(serialized.span())
    }

    fn exists(self: @MoaSigner) -> Option<felt252> {
        let guid = self.guid();
        let guid_exists = exists(SignerType::MOA, guid);
        if guid_exists {
            Option::Some(guid)
        } else {
            Option::None
        }
    }

    /// Adds this signer pub key to the account storage
    fn add_signer(self: @MoaSigner) {
        add_signer(SignerType::MOA, self.guid());
    }
}
