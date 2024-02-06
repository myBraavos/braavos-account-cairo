use core::result::ResultTrait;
use traits::{Into, TryInto};
use array::{ArrayTrait, SpanTrait};
use starknet::storage_access::{
    StoreFelt252, StorageBaseAddress, storage_base_address_from_felt252, storage_base_address_const
};
use braavos_account::signers::interface::{GetSignersResponse};
use braavos_account::signers::signer_type::{SignerType};

mod Consts {
    const EMPTY_GUID: felt252 = 0;
    const DELETED_GUID: felt252 =
        0x800000000000011000000000000000000000000000000000000000000000000; // -1
    const SECP256R1_SIGNERS_BASE_ADDRESS: felt252 = selector!("secp256r1_signers");
    const STARK_SIGNERS_BASE_ADDRESS: felt252 = selector!("stark_signers");
    const WEBAUTHN_SIGNERS_BASE_ADDRESS: felt252 = selector!("webauthn_signers");
}

/// Returns a storage address which is the beginning of a series of guids of signers of the given
/// signer type
fn get_signer_type_base_address(signer_type: SignerType) -> StorageBaseAddress {
    match signer_type {
        SignerType::Empty => { storage_base_address_const::<0>() },
        SignerType::Stark => {
            storage_base_address_from_felt252(Consts::STARK_SIGNERS_BASE_ADDRESS)
        },
        SignerType::Secp256r1 => {
            storage_base_address_from_felt252(Consts::SECP256R1_SIGNERS_BASE_ADDRESS)
        },
        SignerType::Webauthn => {
            storage_base_address_from_felt252(Consts::WEBAUTHN_SIGNERS_BASE_ADDRESS)
        },
    }
}

/// Adds the signer guid to the proper list of guids according to the signer type
fn add_signer(signer_type: SignerType, signer_guid: felt252) {
    if signer_guid == Consts::EMPTY_GUID || signer_guid == Consts::DELETED_GUID {
        panic_with_felt252('CANT USE PRESET VALUE')
    }

    let address = get_signer_type_base_address(signer_type);
    let mut offset = 0;
    loop {
        let guid = StoreFelt252::read_at_offset(0, address, offset).unwrap();
        if guid == Consts::EMPTY_GUID {
            StoreFelt252::write_at_offset(0, address, offset, signer_guid).is_ok();
            break;
        }
        if (guid == signer_guid) {
            panic_with_felt252('SIGNER EXISTS');
        }
        offset = offset + 1;
    }
}

/// Returns the first guid of the given type. Returns 0 if none are found.
fn get_first_signer(signer_type: SignerType) -> felt252 {
    let address = get_signer_type_base_address(signer_type);

    let mut offset = 0;
    let mut first_signer: felt252 = 0;
    loop {
        let guid = StoreFelt252::read_at_offset(0, address, offset).unwrap();
        if guid == Consts::EMPTY_GUID {
            break;
        }
        if guid != Consts::DELETED_GUID {
            first_signer = guid;
            break;
        }
        offset = offset + 1;
    };
    return first_signer;
}

/// Removes signer guid of the given type. If signer not in list then nothing changes.
fn remove_signer(signer_type: SignerType, signer_guid: felt252) {
    if signer_guid == Consts::EMPTY_GUID || signer_guid == Consts::DELETED_GUID {
        panic_with_felt252('CANT USE PRESET VALUE')
    }

    let address = get_signer_type_base_address(signer_type);
    let mut offset = 0;
    loop {
        let guid = StoreFelt252::read_at_offset(0, address, offset).unwrap();
        if guid == Consts::EMPTY_GUID {
            break;
        }
        if (guid == signer_guid) {
            StoreFelt252::write_at_offset(0, address, offset, Consts::DELETED_GUID).is_ok();
            break;
        }
        offset = offset + 1;
    }
}

/// Removes all signers of the given type. If none exist then nothing changes.
fn remove_all_signers(signer_type: SignerType) -> Array<felt252> {
    let address = get_signer_type_base_address(signer_type);
    let mut result = array![];
    let mut offset = 0;
    loop {
        let guid = StoreFelt252::read_at_offset(0, address, offset).unwrap();
        if guid == Consts::EMPTY_GUID {
            break;
        }
        if (guid != Consts::DELETED_GUID) {
            result.append(guid);
            StoreFelt252::write_at_offset(0, address, offset, Consts::DELETED_GUID).is_ok();
        }
        offset = offset + 1;
    };
    return result;
}

/// Get all signers of a given type. Empty array is returned if none exist.
fn get_signers_by_type(signer_type: SignerType) -> Array<felt252> {
    let address = get_signer_type_base_address(signer_type);
    let mut result = array![];
    let mut offset = 0;
    loop {
        let guid = StoreFelt252::read_at_offset(0, address, offset).unwrap();
        if guid == Consts::EMPTY_GUID {
            break;
        }
        if (guid != Consts::DELETED_GUID) {
            result.append(guid);
        }
        offset = offset + 1;
    };
    return result;
}

/// Get all signers saved in account
fn get_signers() -> GetSignersResponse {
    GetSignersResponse {
        stark: get_signers_by_type(SignerType::Stark),
        secp256r1: get_signers_by_type(SignerType::Secp256r1),
        webauthn: get_signers_by_type(SignerType::Webauthn),
    }
}

/// Returns number of strong signers. Strong signers are either Secp256r1 (hardware) or webauthn
fn num_strong_signers() -> usize {
    let signers = get_signers();
    signers.secp256r1.len() + signers.webauthn.len()
}

/// Returns true if given guid exists in correct signer list according to type
fn exists(signer_type: SignerType, signer_guid: felt252) -> bool {
    if signer_guid == Consts::EMPTY_GUID || signer_guid == Consts::DELETED_GUID {
        panic_with_felt252('CANT USE PRESET VALUE')
    }

    let address = get_signer_type_base_address(signer_type);
    let mut offset = 0;
    let mut found: bool = false;
    loop {
        let guid = StoreFelt252::read_at_offset(0, address, offset).unwrap();
        if guid == Consts::EMPTY_GUID {
            break;
        }
        if guid == signer_guid {
            found = true;
            break;
        }
        offset = offset + 1;
    };
    return found;
}

/// Returns true if any signers with the given type exist
fn any(signer_type: SignerType) -> bool {
    let address = get_signer_type_base_address(signer_type);
    let mut offset = 0;
    let mut found: bool = false;
    loop {
        let guid = StoreFelt252::read_at_offset(0, address, offset).unwrap();
        if guid == Consts::EMPTY_GUID {
            break;
        }
        if guid != Consts::DELETED_GUID {
            found = true;
            break;
        }
        offset = offset + 1;
    };
    return found;
}

/// Returns true if any of the strong signers (hardware or webauthn) exist
fn any_strong_signer() -> bool {
    any(SignerType::Secp256r1) || any(SignerType::Webauthn)
}

