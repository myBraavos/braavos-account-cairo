const MOA_ACCOUNT_VERSION: felt252 = '001.001.000';

/// # BraavosMoaAccount Contract
///
/// The BraavosMoaAccount Contract is a smart contract implemented
/// on the StarkNet platform
/// The smart-contract implements multi-signature by requiring signatures from
/// a certain number of signers to execute transactions
///
/// The smart-contract has the following features:
/// * Allows adding and removing authorized persons
/// * Has a signature threshold that must be reached to validate a transaction
/// * Stores information about authorized persons, signature threshold
///   and transactions in the repository
/// * Provides signature verification and transaction execution based
///   on the signature threshold
/// * Provides functions to manage authorized persons and signature thresholds
/// * Divided into several components to manage different aspects of
///   functionality: SRC5Component, MoaSignerManagement, DailyTxnLimit
///   and PendingTransactions

#[starknet::contract(account)]
mod BraavosMoaAccount {
    use braavos_account::account::interface::{IBraavosMOA, IGetVersion};
    use braavos_account::introspection::src5::SRC5Component;
    use braavos_account::signers::interface::IMultisig;
    use braavos_account::signers::moa_signer_management::MoaSignerManagement;
    use braavos_account::signers::multisig::MultisigComponent;
    use braavos_account::signers::signers::{
        MoaExtSigner, MoaExtSignerHelperMethods, MoaExtSignerIntoFelt252, MoaSignerMethods,
        MoaSignerMethodsTrait, StarkPubKey,
    };
    use braavos_account::transactions::daily_txn_limit::DailyTxnLimit;
    use braavos_account::transactions::interface::{IPendingTxnInternalTrait, Transaction};
    use braavos_account::transactions::moa_tx_hash::{
        calculate_moa_preamble_hash, calculate_moa_tx_hash,
    };
    use braavos_account::transactions::pending_txn::PendingTransactions;
    use braavos_account::upgradable::upgradable::UpgradableComponent;
    use braavos_account::utils::arrays::span_to_dict;
    use core::array::{ArrayTrait, SpanSerde, SpanTrait};
    use core::box::BoxTrait;
    use core::option::OptionTrait;
    use core::serde::Serde;
    use core::traits::{Into, TryInto};
    use poseidon::poseidon_hash_span;
    use starknet::account::Call;
    use starknet::syscalls::get_execution_info_v2_syscall;
    use starknet::{
        ContractAddress, SyscallResultTrait, VALIDATED, get_contract_address, get_tx_info,
    };

    // Introspection
    component!(path: SRC5Component, storage: src5, event: Src5Evt);
    #[abi(embed_v0)]
    impl SRC5MOAImpl = SRC5Component::SRC5MOAImpl<ContractState>;

    // Multisig
    component!(path: MultisigComponent, storage: multisig, event: MultisigEvt);
    #[abi(embed_v0)]
    impl MultisigImpl = MultisigComponent::MultisigMoaImpl<ContractState>;
    impl MultisigImplInternal = MultisigComponent::MultisigImplInternal<ContractState>;

    // Signers
    component!(path: MoaSignerManagement, storage: moa_signer_management, event: MoaSigManEvt);
    #[abi(embed_v0)]
    impl MoaSignerManagementImpl =
        MoaSignerManagement::MoaSignerManagementImpl<ContractState>;
    impl MoaSignManagementInternalImpl =
        MoaSignerManagement::MoaSignerManagementInternalImpl<ContractState>;

    // Daily transaction limit
    component!(path: DailyTxnLimit, storage: daily_txn_limit, event: DailyTxnLimitEvt);
    #[abi(embed_v0)]
    impl DailyTxnLimitExternalImpl =
        DailyTxnLimit::DailyTxnLimitExternalImpl<ContractState>;
    impl DailyTxnLimitInternalImpl = DailyTxnLimit::DailyTxnLimitInternalImpl<ContractState>;

    // Pending transaction
    component!(path: PendingTransactions, storage: pending_txn, event: PendingTxnEvt);
    #[abi(embed_v0)]
    impl PendingTxnExternalImpl =
        PendingTransactions::PendingTxnExternalImpl<ContractState>;
    impl PendingTxnInternal = PendingTransactions::PendingTxnInternal<ContractState>;

    // Upgradable
    component!(path: UpgradableComponent, storage: upgradable, event: UpgradableEvt);
    #[abi(embed_v0)]
    impl UpgradableImpl = UpgradableComponent::UpgradableImpl<ContractState>;
    #[abi(embed_v0)]
    impl StorageMigrationMOAImpl =
        UpgradableComponent::StorageMigrationMOAImpl<ContractState>;

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        Src5Evt: SRC5Component::Event,
        #[flat]
        MultisigEvt: MultisigComponent::Event,
        #[flat]
        MoaSigManEvt: MoaSignerManagement::Event,
        #[flat]
        DailyTxnLimitEvt: DailyTxnLimit::Event,
        #[flat]
        PendingTxnEvt: PendingTransactions::Event,
        #[flat]
        UpgradableEvt: UpgradableComponent::Event,
    }


    mod Consts {
        const STARK_ETH_POOL_KEY: felt252 =
            0x2349bd4048674537ab7613333dbf8c8a5dd633f87aceb0588eaec24eb62e49b;
    }
    mod Errors {
        const NOT_ENOUGH_CONFIRMATIONS: felt252 = 'NOT_ENOUGH_CONFIRMATIONS';
        const INVALID_SIGNER: felt252 = 'INVALID_SIGNER';
        const INVALID_SIGNATURE: felt252 = 'INVALID_SIGNATURE';
        const NOT_IMPLEMENTED: felt252 = 'NOT_IMPLEMENTED';
        const INVALID_TX_HASH: felt252 = 'INVALID_TX_HASH';
        const PENDING_WITH_MULTIPLE_SIG: felt252 = 'PENDING_WITH_MULTIPLE_SIG';
        const INVALID_TX_VERSION: felt252 = 'INVALID_TX_VERSION';
        const NO_REENTRANCE: felt252 = 'NO_REENTRANCE';
        const INVALID_TX: felt252 = 'INVALID_TX';
    }

    #[storage]
    struct Storage {
        #[substorage(v0)]
        src5: SRC5Component::Storage,
        #[substorage(v0)]
        multisig: MultisigComponent::Storage,
        #[substorage(v0)]
        moa_signer_management: MoaSignerManagement::Storage,
        #[substorage(v0)]
        daily_txn_limit: DailyTxnLimit::Storage,
        #[substorage(v0)]
        pending_txn: PendingTransactions::Storage,
        #[substorage(v0)]
        upgradable: UpgradableComponent::Storage,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState, signers: Array<(ContractAddress, felt252)>, threshold: usize,
    ) {
        self.moa_signer_management._add_signers(signers, threshold);
    }

    #[abi(embed_v0)]
    impl ExternalGetVersionImpl of IGetVersion<ContractState> {
        /// get_version returns the current version of the account
        fn get_version(self: @ContractState) -> felt252 {
            super::MOA_ACCOUNT_VERSION
        }
    }

    #[abi(embed_v0)]
    impl IMoaAccountImpl of IBraavosMOA<ContractState> {
        /// Starknet account standard validate function. This function parses the incoming
        /// signatures and decides whether this function should be executed.
        /// Applies daily transaction limit to a signer if executing with one signature
        /// @param calls The list of calls to execute
        /// return VALIDATED - a constant that indicates a successful validation
        fn __validate__(ref self: ContractState, calls: Span<Call>) -> felt252 {
            let execution_info = get_execution_info_v2_syscall().unwrap_syscall().unbox();
            assert(execution_info.caller_address.is_zero(), Errors::NO_REENTRANCE);
            let tx_info = execution_info.tx_info.unbox();
            assert(tx_info.paymaster_data.len() == 0, Errors::INVALID_TX);
            let is_query_txn_ver = Into::<felt252, u256>::into(tx_info.version).high == 1;

            let mut signers = MoaExtSignerHelperMethods::resolve_signers_from_sig(
                tx_info.signature,
            );

            let mut pending_tx_hash = 0;
            let mut confirmations = signers.len();

            if (_is_verifier_tx(calls)) {
                // Verifier flow
                PendingTransactions::_assert_sign_pending(calls);
                assert(signers.len() == 1, Errors::INVALID_SIGNATURE);

                let calldata = *calls.at(0).calldata;
                let (proposer_guid, pending_nonce, inner_calls) = self
                    ._parse_sign_pending_calldata(calldata);
                pending_tx_hash =
                    calculate_moa_tx_hash(proposer_guid, pending_nonce, inner_calls, signers.len());
                let tx: Transaction = self.pending_txn._transaction.read();
                if (!is_query_txn_ver) {
                    assert(pending_tx_hash == tx.pending_tx_hash, Errors::INVALID_TX_HASH);
                }
                confirmations += tx.confirmations;
            } else {
                // Tx proposer flow
                PendingTransactions::_assert_max_fee_is_set(calls);
                pending_tx_hash =
                    calculate_moa_tx_hash(
                        signers.at(0).signer.guid(), tx_info.nonce, calls, signers.len(),
                    );
            }

            if (!is_query_txn_ver) {
                self
                    ._assert_signer_validity(
                        pending_tx_hash,
                        signers.span(),
                        validate_external: false,
                        validate_preamble: true,
                    );
            }

            self.pending_txn._assert_new_unique_signers(pending_tx_hash, signers.span());
            let should_execute = confirmations >= self.pending_txn._get_adjusted_threshold();

            // We either allow enough signers to execute or only 1 signer (that can execute or
            // approve)
            if signers.len() == 1 {
                self
                    .daily_txn_limit
                    ._assert_and_update_daily_txn_limit(signers.at(0).signer.guid());
            } else {
                assert(should_execute, Errors::PENDING_WITH_MULTIPLE_SIG);
            }

            // Validating fee limits are set before making external contract calls in __execute__
            self._assert_fees_limits(calls, should_execute);

            VALIDATED
        }

        /// Starknet account standard execute function. This function iterates over the given
        /// calls, executes them and eventually returns the result.
        /// Validates external signatures
        /// @param calls The list of calls to execute
        /// @return Array of call execution results
        fn __execute__(ref self: ContractState, calls: Span<Call>) -> Array<Span<felt252>> {
            let execution_info = get_execution_info_v2_syscall().unwrap_syscall().unbox();
            assert(execution_info.caller_address.is_zero(), Errors::NO_REENTRANCE);
            let tx_info = execution_info.tx_info.unbox();

            assert(tx_info.version != 0, Errors::INVALID_TX_VERSION);

            let signers = MoaExtSignerHelperMethods::resolve_signers_from_sig(tx_info.signature);
            let guids = MoaExtSignerHelperMethods::get_signers_guids(signers.span());

            // sign pending flow guaranteed by __validate__
            let ((proposer_guid, nonce, actual_calls), sign_pending) = if (_is_verifier_tx(calls)) {
                (self._parse_sign_pending_calldata(*calls.at(0).calldata), true)
            } else {
                ((*guids.at(0), tx_info.nonce, calls), false)
            };
            let pending_tx_hash = calculate_moa_tx_hash(
                proposer_guid, nonce, actual_calls, signers.len(),
            );

            let is_query_txn_ver = Into::<felt252, u256>::into(tx_info.version).high == 1;
            if (!is_query_txn_ver) {
                self
                    ._assert_signer_validity(
                        pending_tx_hash,
                        signers.span(),
                        validate_external: true,
                        validate_preamble: false,
                    );
            }

            self
                .pending_txn
                ._confirm_and_execute_if_ready(pending_tx_hash, actual_calls, guids, sign_pending)
        }

        /// @param hash The transaction hash
        /// @param signature The signature of the transaction.
        /// the signature contains information about the signers
        /// of the transaction
        /// @return VALIDATED - a constant that indicates a successful
        /// validation
        ///
        /// Panic if amount of confirmations is less than the threshold
        fn is_valid_signature(
            self: @ContractState, hash: felt252, signature: Span<felt252>,
        ) -> felt252 {
            let signers = MoaExtSignerHelperMethods::resolve_signers_from_sig(signature);
            self
                ._assert_signer_validity(
                    hash, signers.span(), validate_external: true, validate_preamble: true,
                );
            span_to_dict(signers.span(), assert_unique: true);

            assert(
                signers.len() >= self.pending_txn._get_adjusted_threshold(),
                Errors::NOT_ENOUGH_CONFIRMATIONS,
            );
            VALIDATED
        }

        // expected to be deployed via deploy syscall (UDC)
        fn __validate_deploy__(
            self: @ContractState, signers: Array<(ContractAddress, felt252)>, threshold: usize,
        ) -> felt252 {
            panic_with_felt252(Errors::NOT_IMPLEMENTED);
            0
        }

        fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
            panic_with_felt252(Errors::NOT_IMPLEMENTED);
            0
        }
    }

    #[generate_trait]
    impl InternalFn of InternalFnTrait {
        /// Verification of signatures and internal signatures
        /// within a transaction
        /// @param hash The transaction hash
        /// @param signers - list of signers up for validation
        /// @param validate_external - should the external signature be validated using
        /// an external contract call
        /// @param validate_preamble - should the preamble be validated
        fn _assert_signer_validity(
            self: @ContractState,
            hash: felt252,
            mut signers: Span<MoaExtSigner>,
            validate_external: bool,
            validate_preamble: bool,
        ) {
            loop {
                match signers.pop_front() {
                    Option::Some(signer) => {
                        if validate_preamble {
                            assert(signer.signer.exists().is_some(), Errors::INVALID_SIGNER);
                            let ext_sig_hash = calculate_moa_preamble_hash(hash, *signer.ext_sig);
                            assert(
                                signer
                                    .signer
                                    .validate_signature(
                                        ext_sig_hash, *signer.preamble_r, *signer.preamble_s,
                                    ),
                                Errors::INVALID_SIGNATURE,
                            );
                        }
                        if (validate_external) {
                            signer.signer.assert_external_signature(hash, *signer.ext_sig);
                        }
                    },
                    Option::None(_) => { break (); },
                };
            };
        }

        fn _assert_fees_limits(self: @ContractState, calls: Span<Call>, should_execute: bool) {
            let (max_fee_eth, max_fee_stark) = self._extract_fee_limits(calls, should_execute);
            self.pending_txn._assert_valid_max_fee(max_fee_eth, max_fee_stark);
        }

        fn _extract_fee_limits(
            self: @ContractState, calls: Span<Call>, should_execute: bool,
        ) -> (u128, u128) {
            // structure should be:
            // [executing_fee_limit_eth, executing_fee_limit_stark, signing_fee_limit_eth,
            // signing_fee_limit_stark]
            let fee_limit_index = if should_execute {
                0
            } else {
                2
            };

            if (_is_verifier_tx(calls)) {
                let calldata = *calls.at(0).calldata;
                // calldata structure of sign pending is as follows:
                // 0: proposer guid, 1: pending nonce, 2: length of calls span
                // 3: first call to, 4: first call selector, 5: first call calldata length
                // 6: index of the calldata of assert_max_fee which is of length 4
                let inner_calldata = calldata.slice(6, 4);
                let eth_limit: u128 = (*inner_calldata.at(fee_limit_index)).try_into().unwrap();
                let stark_limit: u128 = (*inner_calldata.at(fee_limit_index + 1))
                    .try_into()
                    .unwrap();
                return (eth_limit, stark_limit);
            } else {
                let calldata = *calls.at(0).calldata;
                let eth_limit: u128 = (*calldata.at(fee_limit_index)).try_into().unwrap();
                let stark_limit: u128 = (*calldata.at(fee_limit_index + 1)).try_into().unwrap();
                return (eth_limit, stark_limit);
            }
        }

        fn _parse_sign_pending_calldata(
            self: @ContractState, calldata: Span<felt252>,
        ) -> (felt252, felt252, Span<Call>) {
            // 0 - proposer_guid, 1 - pending_nonce, 2+ - calls
            let mut callspan = calldata.slice(2, calldata.len() - 2);
            let inner_calls = SpanSerde::<Call>::deserialize(ref callspan).unwrap();
            return (*calldata.at(0), *calldata.at(1), inner_calls);
        }
    }

    #[inline(always)]
    fn _is_verifier_tx(calls: Span<Call>) -> bool {
        calls.len() == 1
    }
}

