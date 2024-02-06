const EMPTY_SIGNER_TYPE: felt252 = 0;
const STARK_SIGNER_TYPE: felt252 = 1;
const SECP256R1_SIGNER_TYPE: felt252 = 2;
const WEBAUTHN_SIGNER_TYPE: felt252 = 5;

#[derive(Copy, Drop, PartialEq, starknet::Store)]
enum SignerType {
    #[default]
    Empty,
    Stark,
    Secp256r1,
    Webauthn,
}


impl SerdeSignerType of Serde<SignerType> {
    fn serialize(self: @SignerType, ref output: Array<felt252>) {
        Into::<SignerType, felt252>::into(*self).serialize(ref output);
    }

    fn deserialize(ref serialized: Span<felt252>) -> Option<SignerType> {
        Option::Some(((*serialized.pop_front()?).try_into())?)
    }
}

impl SignerTypeToFelt of Into<SignerType, felt252> {
    fn into(self: SignerType) -> felt252 {
        if self == SignerType::Stark {
            STARK_SIGNER_TYPE
        } else if self == SignerType::Secp256r1 {
            SECP256R1_SIGNER_TYPE
        } else if self == SignerType::Webauthn {
            WEBAUTHN_SIGNER_TYPE
        } else {
            EMPTY_SIGNER_TYPE
        }
    }
}

impl FeltTryIntoSignerType of TryInto<felt252, SignerType> {
    fn try_into(self: felt252) -> Option<SignerType> {
        if self == STARK_SIGNER_TYPE {
            Option::Some(SignerType::Stark)
        } else if self == SECP256R1_SIGNER_TYPE {
            Option::Some(SignerType::Secp256r1)
        } else if self == WEBAUTHN_SIGNER_TYPE {
            Option::Some(SignerType::Webauthn)
        } else {
            Option::Some(SignerType::Empty)
        }
    }
}

