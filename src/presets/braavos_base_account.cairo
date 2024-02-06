use array::{ArrayTrait, SpanTrait};
use starknet::account::Call;

use braavos_account::signers::signers::{StarkPubKey, StarkSignerMethodsTrait};

#[starknet::interface]
trait IBraavosBaseAccount<T> {
    // ISRC6 - does nothing in Base Account
    fn __validate__(ref self: T, calls: Array<Call>) -> felt252;
    fn __execute__(ref self: T, calls: Array<Call>) -> Array<Span<felt252>>;
    // Deploy validation 
    fn __validate_deploy__(
        self: @T, class_hash: felt252, salt: felt252, stark_pub_key: StarkPubKey,
    ) -> felt252;
}


// BraavosBaseAccount is a static class hash used to generate Braavos account addresses.
// This design enables users to recover non-deployed hardware-signer accounts by setting
// a fixed class hash in the DEPLOY_ACCOUNT syscall, while moving non-recoverable parameters
// into the signature that unlike CTOR calldata, doesn't alter the contract address.
// Supported deployment sig structure:
// sig[0: 1] - r,s from stark sign on txn_hash
// sig[2] - actual impl hash - the impl hash we will replace class into
// sig[3: n - 2] -  auxiliary data - hws public key, multisig, daily withdrawal limit etc
// sig[n - 2] -  chain_id - guarantees aux sig is not replayed from other chain ids
// sig[n - 1: n] -  r,s from stark sign on poseidon_hash(sig[2: n-2])
#[starknet::contract(account)]
mod BraavosBaseAccount {
    use starknet::{get_caller_address, get_tx_info, SyscallResultTrait, TxInfo};
    use starknet::syscalls::{library_call_syscall, replace_class_syscall};
    use traits::{Into, TryInto};

    use super::{
        ArrayTrait, Call, IBraavosBaseAccount, SpanTrait, StarkPubKey, StarkSignerMethodsTrait
    };

    mod Consts {
        const INITIALIZER_SELECTOR: felt252 =
            0x2dd76e7ad84dbed81c314ffe5e7a7cacfb8f4836f01af4e913f275f89a3de1a;
    }

    mod Errors {
        const INVALID_TXN_SIG: felt252 = 'INVALID_TXN_SIG';
        const INVALID_AUX_SIG: felt252 = 'INVALID_AUX_SIG';
        const INVALID_AUX_DATA: felt252 = 'INVALID_AUX_DATA';
        const NOT_IMPLEMENTED: felt252 = 'NOT_IMPLEMENTED';
    }

    #[storage]
    struct Storage {}

    #[constructor]
    fn constructor(ref self: ContractState, stark_pub_key: StarkPubKey) {
        let tx_info = get_tx_info().unbox();
        let signature = tx_info.signature;

        // Effective __validate_deploy__ in our base impl scenario
        assert_valid_deploy_base(tx_info, stark_pub_key);

        // Replace to actual impl
        let account_impl = (*signature.at(2)).try_into().unwrap();
        assert(account_impl.is_zero() == false, Errors::INVALID_AUX_DATA);
        replace_class_syscall(account_impl).unwrap_syscall();

        // And initialize the impl
        let mut calldata: Array<felt252> = ArrayTrait::new();
        calldata.append(stark_pub_key.pub_key);
        library_call_syscall(account_impl, Consts::INITIALIZER_SELECTOR, calldata.span())
            .unwrap_syscall();
    }

    /// Validates deployment signature. Supports both UDC and non UDC deployment
    fn assert_valid_deploy_base(tx_info: TxInfo, stark_pub_key: StarkPubKey) {
        let tx_hash = tx_info.transaction_hash;
        let signature = tx_info.signature;
        let sig_len = signature.len();
        // first 3 elements in sig are always [tx hash(r, s), account impl, ...]
        // last 2 elements are sig on the aux data sent in the sig preceded by chain id:
        // [..., account_impl, ..., chain_id, aux(r, s)]
        assert(*signature.at(sig_len - 3) == tx_info.chain_id, Errors::INVALID_AUX_DATA);
        let mut aux_sig_data_span = signature.slice(2, sig_len - 4);
        let mut aux_hash = poseidon::poseidon_hash_span(aux_sig_data_span);
        let aux_sig = array![*signature.at(sig_len - 2), *signature.at(sig_len - 1),];

        if get_caller_address().is_zero() {
            assert(
                stark_pub_key.validate_signature(tx_hash, signature) == true,
                Errors::INVALID_TXN_SIG
            );
        }
        assert(
            stark_pub_key.validate_signature(aux_hash, aux_sig.span()) == true,
            Errors::INVALID_AUX_SIG
        );
    }

    #[abi(embed_v0)]
    impl ExternalMethods of IBraavosBaseAccount<ContractState> {
        fn __execute__(ref self: ContractState, calls: Array<Call>) -> Array<Span<felt252>> {
            panic_with_felt252(Errors::NOT_IMPLEMENTED);
            ArrayTrait::new()
        }

        fn __validate__(ref self: ContractState, calls: Array<Call>) -> felt252 {
            panic_with_felt252(Errors::NOT_IMPLEMENTED);
            0
        }

        fn __validate_deploy__(
            self: @ContractState, class_hash: felt252, salt: felt252, stark_pub_key: StarkPubKey
        ) -> felt252 {
            panic_with_felt252(Errors::NOT_IMPLEMENTED);
            0
        }
    }
}

