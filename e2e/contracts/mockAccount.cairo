#[starknet::interface]
trait IMockAccount<ContractState> {
    /// @notice Assert whether a given signature for a given hash is valid
    /// @param hash The hash of the data
    /// @param signature The signature to validate
    /// @return The string 'VALID' represented as felt when the signature is valid
    fn is_valid_signature(
        self: @ContractState, hash: felt252, signature: Array<felt252>
    ) -> felt252;
}

#[starknet::contract]
mod MockAccount {
    use ecdsa::check_ecdsa_signature;
    use starknet::VALIDATED;

    use super::IMockAccount;

    #[storage]
    struct Storage {
        pub_key: felt252
    }

    #[constructor]
    fn constructor(ref self: ContractState, pub_key: felt252) {
        self.pub_key.write(pub_key);
    }

    #[external(v0)]
    impl IMockAccountImpl of IMockAccount<ContractState> {
        fn is_valid_signature(
            self: @ContractState, hash: felt252, signature: Array<felt252>
        ) -> felt252 {
            assert(
                check_ecdsa_signature(hash, self.pub_key.read(), *signature[0], *signature[1]),
                'Invalid preamble signature'
            );
            return VALIDATED;
        }
    }
}
