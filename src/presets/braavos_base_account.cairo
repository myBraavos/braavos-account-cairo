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

    // Initializer from Braavos Account Factory - generic variant for Base account
    fn initializer_from_factory(
        ref self: T, stark_pub_key: StarkPubKey, deployment_params: Span<felt252>
    );
}


// BraavosBaseAccount is a static class hash used to generate Braavos account addresses.
// This design enables users to recover non-deployed hardware-signer accounts by setting
// a fixed class hash in the DEPLOY_ACCOUNT syscall, while moving non-recoverable parameters
// into the signature that unlike CTOR calldata, doesn't alter the contract address.
// Supported deployment sig structure:
// sig[0: 1] - r,s from stark sign on txn_hash
// sig[2] - actual impl hash - the impl hash we will replace class into
// sig[3: n - 3] -  auxiliary data - hws public key, multisig, daily withdrawal limit etc
// sig[n - 3] -  chain_id - guarantees aux sig is not replayed from other chain ids
// sig[n - 2: n-1] -  r,s from stark sign on poseidon_hash(sig[2: n-2])
#[starknet::contract(account)]
mod BraavosBaseAccount {
    use starknet::{
        get_caller_address, get_tx_info, SyscallResultTrait, TxInfo, get_contract_address
    };
    use starknet::syscalls::{
        library_call_syscall, replace_class_syscall, get_execution_info_v2_syscall
    };
    use braavos_account::utils::utils::{execute_calls};
    use braavos_account::signers::signer_management::SIG_LEN_STARK;
    use traits::{Into, TryInto};

    use super::{
        ArrayTrait, Call, IBraavosBaseAccount, SpanTrait, StarkPubKey, StarkSignerMethodsTrait
    };

    mod Consts {
        const INITIALIZER_SELECTOR: felt252 = selector!("initializer");
        const INITIALIZER_FROM_FACTORY_SELECTOR: felt252 = selector!("initializer_from_factory");
        const BRAAVOS_ACCOUNT_FACTORY_ADDR: felt252 =
            0x3d94f65ebc7552eb517ddb374250a9525b605f25f4e41ded6e7d7381ff1c2e8;
    }

    mod Errors {
        const INVALID_TXN_SIG: felt252 = 'INVALID_TXN_SIG';
        const INVALID_AUX_SIG: felt252 = 'INVALID_AUX_SIG';
        const INVALID_AUX_DATA: felt252 = 'INVALID_AUX_DATA';
        const NO_REENTRANCE: felt252 = 'NO_REENTRANCE';
        const NOT_IMPLEMENTED: felt252 = 'NOT_IMPLEMENTED';
        const INVALID_TX_VERSION: felt252 = 'INVALID_TX_VERSION';
    }

    #[storage]
    struct Storage {
        initialization_stark_key: StarkPubKey,
    }

    #[constructor]
    fn constructor(ref self: ContractState, stark_pub_key: StarkPubKey) {
        let caller = get_caller_address();
        if caller != Consts::BRAAVOS_ACCOUNT_FACTORY_ADDR.try_into().unwrap() {
            let tx_info = get_tx_info().unbox();
            let signature = tx_info.signature;
            if caller.is_zero() {
                assert(
                    stark_pub_key.validate_signature(tx_info.transaction_hash, signature) == true,
                    Errors::INVALID_TXN_SIG
                );
            }

            // Effective __validate_deploy__ in our base impl scenario - trim leading (r,s) as they
            // are validated above
            _assert_valid_deploy_params(
                tx_info, stark_pub_key, signature.slice(2, signature.len() - 2)
            );

            // Replace to actual impl
            let account_impl = (*signature.at(2)).try_into().unwrap();
            assert(account_impl.is_zero() == false, Errors::INVALID_AUX_DATA);
            replace_class_syscall(account_impl).unwrap_syscall();

            // And initialize the impl
            let mut calldata: Array<felt252> = ArrayTrait::new();
            calldata.append(stark_pub_key.pub_key);
            library_call_syscall(account_impl, Consts::INITIALIZER_SELECTOR, calldata.span())
                .unwrap_syscall();
        } else {
            // Initializing of "non-recoverable" parameters (e.g. HWS pub key, daily spend limit)
            // is expected to occur in the initializer_from_factory entrypoint. We use this
            // storage variable to verify the entrypoint is called with the intended pub key.
            self.initialization_stark_key.write(stark_pub_key);
        }
    }

    /// Validates additional deployment params. Supports both UDC and non UDC deployment
    fn _assert_valid_deploy_params(
        tx_info: TxInfo, stark_pub_key: StarkPubKey, deploy_params: Span<felt252>
    ) {
        let params_len = deploy_params.len();
        assert(*deploy_params.at(params_len - 3) == tx_info.chain_id, Errors::INVALID_AUX_DATA);
        let mut aux_sig_data_span = deploy_params.slice(0, params_len - 2);
        let mut aux_hash = poseidon::poseidon_hash_span(aux_sig_data_span);
        let aux_sig = array![*deploy_params.at(params_len - 2), *deploy_params.at(params_len - 1),];

        assert(
            stark_pub_key.validate_signature(aux_hash, aux_sig.span()) == true,
            Errors::INVALID_AUX_SIG,
        );
    }

    #[abi(embed_v0)]
    impl ExternalMethods of IBraavosBaseAccount<ContractState> {
        fn initializer_from_factory(
            ref self: ContractState, stark_pub_key: StarkPubKey, deployment_params: Span<felt252>
        ) {
            // This function does not limit itself to the factory address to prevent bricking by
            // a malicous factory. A malicous factory could call the ctor without calling this function.
            // Therefor we allow the init func to be called on a non initialized base account by the account
            // itself or by any other 3rd party account
            assert(
                stark_pub_key.pub_key == self.initialization_stark_key.read().pub_key,
                Errors::NO_REENTRANCE
            );

            let tx_info = get_tx_info().unbox();
            _assert_valid_deploy_params(tx_info, stark_pub_key, deployment_params);

            // Replace to actual impl
            let account_chash = (*deployment_params.at(0)).try_into().unwrap();
            replace_class_syscall(account_chash).unwrap_syscall();

            // And initialize the impl
            let mut depl_cdata = array![stark_pub_key.pub_key];
            depl_cdata.append_span(deployment_params);
            library_call_syscall(
                class_hash: account_chash,
                function_selector: Consts::INITIALIZER_FROM_FACTORY_SELECTOR,
                calldata: depl_cdata.span(),
            )
                .unwrap_syscall();

            // Avoid storage diff + no reentrance once init is done
            self.initialization_stark_key.write(StarkPubKey { pub_key: 0 });
        }

        // We allow the base account contract to execute the initializer_from_factory call, this is validated
        // in __validate__
        fn __execute__(ref self: ContractState, calls: Array<Call>) -> Array<Span<felt252>> {
            let execution_info = get_execution_info_v2_syscall().unwrap_syscall().unbox();
            assert(execution_info.caller_address.is_zero(), Errors::NO_REENTRANCE);
            let tx_info = execution_info.tx_info.unbox();
            assert(tx_info.version != 0, Errors::INVALID_TX_VERSION);
            execute_calls(calls.span())
        }

        // We perform strict validation on the call attempt to make sure only initializer_from_factory
        // can be called in the scenario where a base account was constructed but initialization did not occur. 
        // We validate that the tx was signed with the correct key set in ctor to prevent anyone else making calls
        // that might fail during execute and drain the account (for example sending faulty deployment params)
        fn __validate__(ref self: ContractState, calls: Array<Call>) -> felt252 {
            assert(
                calls.len() == 1
                    && *calls.at(0).to == get_contract_address()
                    && *calls.at(0).selector == Consts::INITIALIZER_FROM_FACTORY_SELECTOR,
                Errors::NOT_IMPLEMENTED
            );

            let init_pub_key = self.initialization_stark_key.read();
            let tx_info = get_tx_info().unbox();
            let version = Into::<felt252, u256>::into(tx_info.version);
            let is_query_txn_ver = version.high == 1;
            assert(
                is_query_txn_ver
                    || (tx_info.signature.len() == SIG_LEN_STARK
                        && init_pub_key
                            .validate_signature(tx_info.transaction_hash, tx_info.signature)),
                Errors::INVALID_TXN_SIG
            );
            
            return starknet::VALIDATED;
        }

        fn __validate_deploy__(
            self: @ContractState, class_hash: felt252, salt: felt252, stark_pub_key: StarkPubKey
        ) -> felt252 {
            panic_with_felt252(Errors::NOT_IMPLEMENTED);
            0
        }
    }
}

