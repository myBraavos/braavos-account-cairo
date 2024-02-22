/// # PendingTransactions Component
///
/// The PendingTransactions Component is responsible
/// for managing multi-signature transactions

#[starknet::component]
mod PendingTransactions {
    use core::array::ArrayTrait;
    use core::option::OptionTrait;
    use core::traits::{TryInto, Into};
    use starknet::account::Call;
    use starknet::{get_tx_info, get_contract_address, call_contract_syscall};
    use braavos_account::utils::asserts::assert_self_caller;
    use braavos_account::transactions::moa_tx_hash::calculate_moa_tx_hash;
    use braavos_account::utils::utils::{execute_calls, extract_fee_from_tx};
    use braavos_account::signers::interface::{IMoaSignManagementExternal, IMultisig};
    use braavos_account::signers::signers::{
        MoaExtSigner, MoaExtSignerHelperMethods, MoaSignerMethods
    };
    use braavos_account::transactions::interface::{
        IPendingTxnExternalTrait, IPendingTxnInternalTrait, Transaction
    };

    mod Consts {
        // 0.03 ETH limit for v1 transactions
        const NON_EXECUTING_SIGNER_MAX_FEE_LIMIT_ETH: felt252 = 30000000000000000;
        // 30 STRK limit for v3 transactions
        const NON_EXECUTING_SIGNER_MAX_FEE_LIMIT_STARK: felt252 = 30000000000000000000;
        const SIGN_PENDING_FUNCTION_SELECTOR: felt252 =
            selector!("sign_pending_multisig_transaction");
        const ASSERT_MAX_FEE_FUNCTION_SELECTOR: felt252 = selector!("assert_max_fee");
    }

    #[derive(Drop, starknet::Event)]
    struct MultisigPendingTransaction {
        #[key]
        pending_hash: felt252,
        signers: Span<felt252>,
        is_executed: bool,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        MultisigPendingTransaction: MultisigPendingTransaction,
    }

    mod Errors {
        const NOT_APPROVAL: felt252 = 'NOT_APPROVAL';
        const NO_MAX_FEE: felt252 = 'INVALID_MAX_FEE';
        const MAX_FEE_TOO_HIGH: felt252 = 'MAX_FEE_TOO_HIGH';
        const HASH_MISMATCH: felt252 = 'HASH_MISMATCH';
        const MAX_FEE_EXCEEDS_EXPECTED: felt252 = 'MAX_FEE_EXCEEDS_EXPECTED';
        const CALL_FAILED: felt252 = 'CALL_FAILED';
        const DUPLICATE_SIG: felt252 = 'DUPLICATE_SIG';
        const ALREADY_CONFIRMED: felt252 = 'ALREADY_CONFIRMED';
        const INVALID_TX_VERSION: felt252 = 'INVALID_TX_VERSION';
        const NOT_ALLOWED: felt252 = 'NOT_ALLOWED';
    }

    #[storage]
    struct Storage {
        _transaction: Transaction,
        _is_confirmed: LegacyMap<(felt252, felt252), bool>,
    }

    /// @param calls The list of calls to execute
    /// Panic if the call is not sign_pending_multisig_transaction
    fn _assert_sign_pending(calls: Span<Call>) {
        assert(
            calls.len() == 1
                && *calls.at(0).to == get_contract_address()
                && *calls.at(0).selector == Consts::SIGN_PENDING_FUNCTION_SELECTOR,
            Errors::NOT_APPROVAL
        );
    }

    /// @param calls The list of calls to execute
    /// Panic if first call isn`t assert max fee
    /// Panic if fee structure incorrect
    fn _assert_max_fee_is_set(calls: Span<Call>) {
        assert(
            calls.len() >= 2
                && *calls.at(0).to == get_contract_address()
                && *calls.at(0).selector == Consts::ASSERT_MAX_FEE_FUNCTION_SELECTOR,
            Errors::NO_MAX_FEE
        );

        let max_fee_assert_calldata = *calls.at(0).calldata;
        assert(max_fee_assert_calldata.len() == 4, Errors::NO_MAX_FEE);

        // We allow fine tuning of the non executing signer max fee but still protect
        // from drainage
        let signing_max_fee_eth: u128 = (*max_fee_assert_calldata.at(2)).try_into().unwrap();
        assert(
            signing_max_fee_eth <= Consts::NON_EXECUTING_SIGNER_MAX_FEE_LIMIT_ETH
                .try_into()
                .unwrap(),
            Errors::NO_MAX_FEE
        );
        let signing_max_fee_stark: u128 = (*max_fee_assert_calldata.at(3)).try_into().unwrap();
        assert(
            signing_max_fee_stark <= Consts::NON_EXECUTING_SIGNER_MAX_FEE_LIMIT_STARK
                .try_into()
                .unwrap(),
            Errors::NO_MAX_FEE
        );
    }

    impl PendingTxnInternal<
        TContractState,
        +HasComponent<TContractState>,
        +Drop<TContractState>,
        +IMoaSignManagementExternal<TContractState>,
        +IMultisig<TContractState>,
    > of IPendingTxnInternalTrait<ComponentState<TContractState>> {
        /// @param tx_hash The hash of signed tx. May be already pending
        /// @param signers The list of signers parsed from the signature
        ///
        /// Panic if duplicate signer is passed
        /// Panic if a signer already signed pending tx
        fn _assert_new_unique_signers(
            self: @ComponentState<TContractState>, tx_hash: felt252, mut signers: Span<MoaExtSigner>
        ) {
            let mut duplicates: Felt252Dict<bool> = Default::default();

            loop {
                match signers.pop_front() {
                    Option::Some(signer) => {
                        let signer_guid = signer.signer.guid();
                        assert(
                            !self._is_confirmed.read((tx_hash, signer_guid)),
                            Errors::ALREADY_CONFIRMED
                        );
                        assert(duplicates.get(signer_guid) == false, Errors::DUPLICATE_SIG);
                        duplicates.insert(signer_guid, true);
                    },
                    Option::None(_) => { break (); },
                };
            };
        }

        /// Updates the state of a multi-signature transaction based
        /// on confirmations received
        /// Confirmations are already verified to be unique and new
        /// @param confirmations An array of signer IDs who have confirmed
        /// the transaction
        fn _apply_confirmations(
            ref self: ComponentState<TContractState>, mut confirmations: Array<felt252>
        ) {
            let mut transaction: Transaction = self._transaction.read();
            transaction.confirmations += confirmations.len();
            self._transaction.write(transaction);

            loop {
                match confirmations.pop_front() {
                    Option::Some(signer) => {
                        self._is_confirmed.write((transaction.pending_tx_hash, signer), true);
                    },
                    Option::None(_) => { break (); },
                };
            };
        }

        /// Reset stored pending tx info and execute calls
        /// @param calls The list of calls to execute
        /// @return Array of results of execution of transaction calls
        fn _execute_transaction(
            ref self: ComponentState<TContractState>, mut calls: Span::<Call>
        ) -> Array<Span<felt252>> {
            self._transaction.write(Transaction { pending_tx_hash: 0, confirmations: 0, });

            // first assert_max_fee call was executed in __validate__
            calls.pop_front().expect(Errors::NO_MAX_FEE);

            execute_calls(calls)
        }

        /// Panic if the current transaction uses a higher max fee
        /// than the given limit
        fn _assert_valid_max_fee(
            self: @ComponentState<TContractState>, fee_limit_eth: u128, fee_limit_stark: u128
        ) {
            let tx_info = get_tx_info().unbox();
            let version = Into::<felt252, u256>::into(tx_info.version);
            let fee = extract_fee_from_tx(@tx_info, version);
            if version.low == 1 {
                assert(fee <= fee_limit_eth.into(), Errors::MAX_FEE_TOO_HIGH);
            } else if version.low == 3 {
                assert(fee <= fee_limit_stark.into(), Errors::MAX_FEE_TOO_HIGH);
            } else {
                panic_with_felt252(Errors::INVALID_TX_VERSION);
            }
        }

        /// Calculate new confirmations and execute tx if threshold is reached
        /// Otherwise store confirmations info
        /// @emit Event that shows tx execution status and list of signers
        fn _confirm_and_execute_if_ready(
            ref self: ComponentState<TContractState>,
            pending_tx_hash: felt252,
            calls: Span<Call>,
            signers_guids: Array<felt252>,
            sign_pending: bool
        ) -> Array<Span<felt252>> {
            let existing_confirmation: u32 = if (sign_pending) {
                let tx: Transaction = self._transaction.read();
                tx.confirmations
            } else {
                0
            };

            let threshold = self._get_adjusted_threshold();
            let should_execute = signers_guids.len() + existing_confirmation >= threshold;

            self
                .emit(
                    MultisigPendingTransaction {
                        pending_hash: pending_tx_hash,
                        signers: signers_guids.span(),
                        is_executed: should_execute
                    }
                );

            if (should_execute) {
                self._execute_transaction(calls)
            } else {
                if (!sign_pending) {
                    self
                        ._transaction
                        .write(Transaction { pending_tx_hash: pending_tx_hash, confirmations: 0 });
                }
                self._apply_confirmations(signers_guids);
                array![]
            }
        }

        fn _get_adjusted_threshold(self: @ComponentState<TContractState>) -> usize {
            let threshold = self.get_contract().get_multisig_threshold();
            if (threshold == 0) {
                return 1;
            }
            threshold
        }
    }

    #[embeddable_as(PendingTxnExternalImpl)]
    impl PendingTxnExternal<
        TContractState,
        +HasComponent<TContractState>,
        +Drop<TContractState>,
        +IMoaSignManagementExternal<TContractState>,
        +IMultisig<TContractState>,
    > of IPendingTxnExternalTrait<ComponentState<TContractState>> {
        /// @param tx_hash Transaction hash
        /// @param signer_guid Signer guid derived from address and pub_key
        /// @return True if a transaction has been confirmed by the signer
        fn is_confirmed(
            self: @ComponentState<TContractState>, tx_hash: felt252, signer_guid: felt252
        ) -> bool {
            self._is_confirmed.read((tx_hash, signer_guid))
        }

        /// Get current pending transaction
        /// @return Struct Transaction with pending_tx_hash and confirmations
        fn get_pending_multisig_transaction(self: @ComponentState<TContractState>) -> Transaction {
            self._transaction.read()
        }

        /// @param pending_nonce The nonce of the pending multi-sig transaction
        /// to be signed.
        /// @param calls The list of calls to execute
        ///
        /// The actual validation logic is in __validate__
        /// The actual execution logic in __execute__
        fn sign_pending_multisig_transaction(
            ref self: ComponentState<TContractState>,
            proposer_guid: felt252,
            pending_nonce: felt252,
            calls: Span<Call>
        ) -> Array<Span<felt252>> {
            panic_with_felt252(Errors::NOT_ALLOWED);
            array![]
        }

        /// @param Expected value of the maximum transaction fee
        ///
        /// Panic if the maximum transaction fee is greater
        /// than the allowable transaction fee
        ///
        /// The actual validation logic is in __validate__
        /// The actual execution logic in __execute__
        fn assert_max_fee(
            self: @ComponentState<TContractState>,
            expected_max_fee_in_eth: u128,
            expected_max_fee_in_stark: u128,
            signer_max_fee_in_eth: u128,
            signer_max_fee_in_stark: u128
        ) {
            panic_with_felt252(Errors::NOT_ALLOWED);
        }
    }
}
