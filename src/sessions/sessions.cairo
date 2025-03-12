#[starknet::component]
mod SessionComponent {
    use core::option::OptionTrait;
    use core::traits::TryInto;
    use core::dict::Felt252Dict;
    use core::integer::U256Zeroable;
    use braavos_account::sessions::interface::{
        GasSponsoredSessionExecutionRequest, GasSponsoredSessionExecutionRequestV2,
        GasSponsoredSessionStarted, IGasSponsoredSessionExecute,
        IGasSponsoredSessionExecuteInternal, ISessionExecute, ISessionExecuteInternal,
        ISessionHelper, ISessionManagement, SessionExecuteRequest, SessionExecuteRequestV2,
        SessionKeyVersion, SessionRevoked, SessionStarted, TokenAmount,
    };
    use braavos_account::utils::asserts::{
        assert_self_caller, assert_no_self_calls, assert_timestamp, assert_timestamp_2
    };
    use braavos_account::account::interface::IBraavosAccountInternal;
    use braavos_account::sessions::hash::{
        calculate_gas_sponsored_session_execution_hash, calculate_session_execute_hash
    };
    use braavos_account::utils::utils::{execute_calls, extract_fee_from_tx};
    use braavos_account::sessions::utils::{
        GasSponsoredSessionExecutionRequestIntoV2, SessionExecuteRequestIntoV2,
        is_dai_transfer_from_itself_call, is_erc20_token_removal_call, validate_allowed_methods,
        get_session_execute_version
    };
    use braavos_account::signers::signer_address_mgt::get_signers;
    use braavos_account::signers::signer_management::SIG_LEN_STARK;
    use braavos_account::signers::interface::IMultisig;
    use poseidon::poseidon_hash_span;
    use braavos_account::signers::signers::{StarkPubKey, StarkSignerMethods};
    use starknet::{
        ContractAddress, get_contract_address, get_caller_address, get_block_timestamp, get_tx_info,
        TxInfo
    };
    use starknet::account::Call;
    use starknet::storage::Map;


    #[storage]
    struct Storage {
        revocations: Map<felt252, bool>,
        validated_sessions: Map<(felt252, felt252), bool>,
        validated_sessions_strk_gas_spent: Map<felt252, u128>,
        session_token_spent: Map<(felt252, ContractAddress), u256>
    }

    mod Errors {
        const NOT_ALLOWED: felt252 = 'NOT_ALLOWED';
        const SESSION_REVOKED: felt252 = 'SESSION_REVOKED';
        const INVALID_SIG: felt252 = 'INVALID_SIG';
        const INVALID_INPUT: felt252 = 'INVALID_INPUT';
        const INVALID_FEE: felt252 = 'INVALID_FEE';
        const BAD_SPENDING: felt252 = 'BAD_SPENDING';
        const INVALID_TX_VERSION: felt252 = 'INVALID_TX_VERSION';
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        GasSponsoredSessionStarted: GasSponsoredSessionStarted,
        SessionStarted: SessionStarted,
        SessionRevoked: SessionRevoked,
    }

    #[embeddable_as(SessionManagementExternal)]
    impl SessionManagementExternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        +Drop<TContractState>,
        +IMultisig<TContractState>,
    > of ISessionManagement<ComponentState<TContractState>> {
        fn revoke_session(ref self: ComponentState<TContractState>, session_hash: felt252) {
            assert_self_caller();
            self.revocations.write(session_hash, true);
            self.emit(SessionRevoked { session_hash: session_hash });
        }

        fn is_session_revoked(
            self: @ComponentState<TContractState>, session_hash: felt252
        ) -> bool {
            self.revocations.read(session_hash)
        }

        fn get_spending_limit_amount_spent(
            self: @ComponentState<TContractState>,
            session_hash: felt252,
            token_address: ContractAddress
        ) -> u256 {
            self.session_token_spent.read((session_hash, token_address))
        }

        fn get_session_gas_spent(
            self: @ComponentState<TContractState>, session_hash: felt252,
        ) -> u128 {
            self.validated_sessions_strk_gas_spent.read(session_hash)
        }

        fn is_session_validated(
            self: @ComponentState<TContractState>, session_hash: felt252
        ) -> bool {
            self.validated_sessions.read((session_hash, self._get_signer_state_hash()))
        }
    }

    #[embeddable_as(SessionExecuteExternal)]
    impl SessionExecuteExternalImpl<
        TContractState, +HasComponent<TContractState>, +Drop<TContractState>,
    > of ISessionExecute<ComponentState<TContractState>> {
        fn session_execute(
            self: @ComponentState<TContractState>, session_execute_request: SessionExecuteRequest,
        ) {
            panic_with_felt252(Errors::NOT_ALLOWED);
        }

        fn session_execute_v2(
            self: @ComponentState<TContractState>, session_execute_request: SessionExecuteRequestV2,
        ) {
            panic_with_felt252(Errors::NOT_ALLOWED);
        }
    }


    #[embeddable_as(SessionExecuteInternal)]
    impl SessionExecuteInternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        +IBraavosAccountInternal<TContractState>,
        +IMultisig<TContractState>,
        +Drop<TContractState>,
    > of ISessionExecuteInternal<ComponentState<TContractState>> {
        // This function validates inside sessions during the __validate__. It validates the
        // following:
        // 1. Session info in the "session_execute" calldata is valid and parseable.
        // 2. No self calls.
        // 3. Session had started and not expired yet.
        // 4. Calls are within the list of allowed methods.
        // 5. Session is not revoked.
        // 6. A valid user signature on the session object hash is attached or the session hash is
        // already cached.
        // 7. Transaction hash is signed by the session owner private key specified
        // in the session object.
        // 8. Fee spent during this session isn't greater than the specified
        // fee limits.
        // 9. Tokens spent during this session aren't greater than specified in the
        // spending limit array.
        fn _validate_session_execute(
            ref self: ComponentState<TContractState>,
            tx_info: TxInfo,
            timestamp: u64,
            calls: Span<Call>,
        ) -> felt252 {
            let session_key_version = get_session_execute_version(calls);
            let mut session_execute_calldata = *calls.at(0).calldata;
            let session_execute_request: SessionExecuteRequestV2 =
                if session_key_version == SessionKeyVersion::V2 {
                Serde::<SessionExecuteRequestV2>::deserialize(ref session_execute_calldata)
                    .expect(Errors::INVALID_INPUT)
            } else {
                Serde::<SessionExecuteRequest>::deserialize(ref session_execute_calldata)
                    .expect(Errors::INVALID_INPUT)
                    .into()
            };
            let tx_ver = tx_info.version;
            assert(Into::<felt252, u256>::into(tx_ver).low == 3, Errors::INVALID_TX_VERSION);

            let hash = tx_info.transaction_hash;
            let signature = tx_info.signature;

            let executing_calls = calls.slice(1, calls.len() - 1);
            assert_no_self_calls(executing_calls);

            assert_timestamp_2(
                session_execute_request.session_request.execute_after,
                session_execute_request.session_request.execute_before,
                timestamp
            );
            validate_allowed_methods(
                session_execute_request.session_request.allowed_method_guids,
                session_execute_request.session_request.allowed_method_calldata_validations,
                executing_calls,
                session_execute_request.call_hints,
                session_key_version
            );
            let session_hash = calculate_session_execute_hash(
                @session_execute_request.session_request, session_key_version
            );

            assert(!self.is_session_revoked(session_hash), Errors::SESSION_REVOKED);

            let is_execute_session_validated = self.is_session_validated(session_hash);
            assert(
                is_execute_session_validated
                    || self
                        .get_contract()
                        ._is_valid_signature_common(
                            session_hash,
                            session_execute_request.session_request_signature,
                            timestamp,
                            tx_ver
                        ) == starknet::VALIDATED,
                Errors::INVALID_SIG
            );

            let session_stark_owner = StarkPubKey {
                pub_key: session_execute_request.session_request.owner_pub_key
            };

            assert(
                session_stark_owner.validate_signature(hash, signature)
                    && signature.len() == SIG_LEN_STARK,
                Errors::INVALID_SIG
            );

            if (!is_execute_session_validated) {
                self._cache_session(session_hash);
                self
                    .emit(
                        SessionStarted {
                            session_hash: session_hash,
                            owner_pub_key: session_stark_owner.pub_key,
                            execute_after: session_execute_request.session_request.execute_after,
                            execute_before: session_execute_request.session_request.execute_before,
                            tx_hash: hash,
                            v3_gas_limit: session_execute_request.session_request.v3_gas_limit,
                        }
                    );
            }

            let fee: u128 = extract_fee_from_tx(@tx_info, tx_ver.into()).try_into().unwrap();
            self
                ._validate_gas_spending(
                    session_hash, fee, session_execute_request.session_request.v3_gas_limit
                );

            self
                ._validate_spending_limits(
                    session_hash,
                    executing_calls,
                    session_execute_request.session_request.spending_limits,
                );
            starknet::VALIDATED
        }

        // executes the transaction calls, skipping the first call which only contains
        // the session metadata
        fn _execute_session_calls(
            ref self: ComponentState<TContractState>, calls: Span<Call>,
        ) -> Array<Span<felt252>> {
            execute_calls(calls.slice(1, calls.len() - 1))
        }
    }

    impl SessionHelperImpl<
        TContractState,
        +IMultisig<TContractState>,
        +HasComponent<TContractState>,
        +Drop<TContractState>,
    > of ISessionHelper<ComponentState<TContractState>> {
        // This function is responsible to validate that token spending in the context
        // of this session are not larger than the allowed amounts specified in the spending limit
        // array.
        // It also updates the latest token spending status in storage.
        // This function only tracks erc-20 transfer, approve and increase_allowance functions
        // calldata.
        fn _validate_spending_limits(
            ref self: ComponentState<TContractState>,
            session_hash: felt252,
            mut calls: Span<Call>,
            mut spending_limits: Span<TokenAmount>,
        ) {
            let mut spending_tracker: Felt252Dict<Nullable<(u256, u256)>> = Default::default();
            let mut budget_addresses: Array<ContractAddress> = array![];
            loop {
                match spending_limits.pop_front() {
                    Option::Some(spending_limit) => {
                        let curr_token_spent = self
                            .session_token_spent
                            .read((session_hash, *spending_limit.token_address));
                        spending_tracker
                            .insert(
                                (*spending_limit.token_address).into(),
                                NullableTrait::new((curr_token_spent, *spending_limit.amount))
                            );
                        budget_addresses.append(*spending_limit.token_address);
                    },
                    Option::None(_) => { break; },
                };
            };

            loop {
                match calls.pop_front() {
                    Option::Some(call) => {
                        let token_spending_tracker = spending_tracker.get((*call.to).into());
                        if !token_spending_tracker.is_null() {
                            let calldata = *call.calldata;
                            let erc20_amount = if is_erc20_token_removal_call(call) {
                                u256 {
                                    low: (*(calldata).at(1)).try_into().unwrap(),
                                    high: (*(calldata).at(2)).try_into().unwrap()
                                }
                            } else if is_dai_transfer_from_itself_call(call) {
                                u256 {
                                    low: (*(calldata).at(2)).try_into().unwrap(),
                                    high: (*(calldata).at(3)).try_into().unwrap()
                                }
                            } else {
                                U256Zeroable::zero()
                            };
                            if !U256Zeroable::is_zero(erc20_amount) {
                                let (spent_amount, spending_limit) = token_spending_tracker.deref();
                                assert(
                                    erc20_amount + spent_amount <= spending_limit,
                                    Errors::BAD_SPENDING
                                );
                                spending_tracker
                                    .insert(
                                        (*call.to).into(),
                                        NullableTrait::new(
                                            (erc20_amount + spent_amount, spending_limit)
                                        )
                                    );
                            }
                        }
                    },
                    Option::None(_) => { break; },
                };
            };

            loop {
                match budget_addresses.pop_front() {
                    Option::Some(token_address) => {
                        let (spent_amount, _) = spending_tracker.get(token_address.into()).deref();
                        self.session_token_spent.write((session_hash, token_address), spent_amount);
                    },
                    Option::None(_) => { break; },
                };
            };
        }

        // This function is responsible to validate that fee spending in the context
        // of this session is not larger than the allowed amounts. It also updates
        // the latest fee spending status in storage.
        fn _validate_gas_spending(
            ref self: ComponentState<TContractState>,
            session_hash: felt252,
            fee: u128,
            request_gas_limit: u128
        ) {
            let gas_spent = self.validated_sessions_strk_gas_spent.read(session_hash) + fee;

            assert(gas_spent <= request_gas_limit, Errors::INVALID_FEE);
            self.validated_sessions_strk_gas_spent.write(session_hash, gas_spent);
        }

        fn _cache_session(ref self: ComponentState<TContractState>, session_hash: felt252) {
            self.validated_sessions.write((session_hash, self._get_signer_state_hash()), true);
        }

        fn _get_signer_state_hash(self: @ComponentState<TContractState>) -> felt252 {
            let signer_state = get_signers();
            let mut signer_guids: Array<felt252> = array![];
            signer_guids.append(self.get_contract().get_multisig_threshold().into());
            signer_guids.append_span(signer_state.stark.span());
            signer_guids.append_span(signer_state.secp256r1.span());
            signer_guids.append_span(signer_state.webauthn.span());
            poseidon_hash_span(signer_guids.span())
        }
    }


    impl GasSponsoredSessionExecInternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        +IBraavosAccountInternal<TContractState>,
        +IMultisig<TContractState>,
        +Drop<TContractState>,
    > of IGasSponsoredSessionExecuteInternal<ComponentState<TContractState>> {
        // This function validates and executes outside execution session transactions. It validates
        // the following:
        // 1. No self calls.
        // 2. Session had started and not expired yet.
        // 3. Calls are within the list of allowed methods.
        // 4. Session is not revoked.
        // 5. A valid user signature on the session object hash is attached or the session hash is
        // already cached.
        // 6. Tokens spent during this session aren't greater than specified in the spending limit
        // array.
        fn _execute_gas_sponsored_session_tx_internal(
            ref self: ComponentState<TContractState>,
            gas_sponsored_session_request: GasSponsoredSessionExecutionRequestV2,
            signature: Span<felt252>,
            session_key_version: SessionKeyVersion,
        ) -> Array<Span<felt252>> {
            assert_no_self_calls(gas_sponsored_session_request.calls);
            let timestamp = assert_timestamp(
                gas_sponsored_session_request.execute_after,
                gas_sponsored_session_request.execute_before
            );
            validate_allowed_methods(
                gas_sponsored_session_request.allowed_method_guids,
                gas_sponsored_session_request.allowed_method_calldata_validations,
                gas_sponsored_session_request.calls,
                gas_sponsored_session_request.call_hints,
                session_key_version
            );

            let caller = get_caller_address();
            let session_hash = calculate_gas_sponsored_session_execution_hash(
                @gas_sponsored_session_request, caller, session_key_version
            );
            let tx_info = get_tx_info().unbox();
            let tx_ver = tx_info.version;

            assert(!self.is_session_revoked(session_hash), Errors::SESSION_REVOKED);

            let is_session_validated = self.is_session_validated(session_hash);
            assert(
                is_session_validated
                    || self
                        .get_contract()
                        ._is_valid_signature_common(
                            session_hash, signature, timestamp, tx_ver
                        ) == starknet::VALIDATED,
                Errors::INVALID_SIG
            );

            if (!is_session_validated) {
                self._cache_session(session_hash);
                self
                    .emit(
                        GasSponsoredSessionStarted {
                            session_hash: session_hash,
                            caller: caller,
                            execute_after: gas_sponsored_session_request.execute_after,
                            execute_before: gas_sponsored_session_request.execute_before,
                            tx_hash: tx_info.transaction_hash
                        }
                    );
            }

            self
                ._validate_spending_limits(
                    session_hash,
                    gas_sponsored_session_request.calls,
                    gas_sponsored_session_request.spending_limits,
                );

            execute_calls(gas_sponsored_session_request.calls)
        }
    }

    #[embeddable_as(GasSponsoredSessionExec)]
    impl GasSponsoredSessionExecImpl<
        TContractState,
        +HasComponent<TContractState>,
        +IBraavosAccountInternal<TContractState>,
        +IMultisig<TContractState>,
        +Drop<TContractState>,
    > of IGasSponsoredSessionExecute<ComponentState<TContractState>> {
        fn execute_gas_sponsored_session_tx(
            ref self: ComponentState<TContractState>,
            gas_sponsored_session_request: GasSponsoredSessionExecutionRequest,
            signature: Span<felt252>,
        ) -> Array<Span<felt252>> {
            self
                ._execute_gas_sponsored_session_tx_internal(
                    gas_sponsored_session_request.into(), signature, SessionKeyVersion::V1,
                )
        }

        fn execute_gas_sponsored_session_tx_v2(
            ref self: ComponentState<TContractState>,
            gas_sponsored_session_request: GasSponsoredSessionExecutionRequestV2,
            signature: Span<felt252>,
        ) -> Array<Span<felt252>> {
            self
                ._execute_gas_sponsored_session_tx_internal(
                    gas_sponsored_session_request, signature, SessionKeyVersion::V2,
                )
        }
    }
}
