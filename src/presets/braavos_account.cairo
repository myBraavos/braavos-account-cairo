const ACCOUNT_VERSION: felt252 = '001.000.000';

/// # BraavosAccount preset
///
/// This preset compiles the various components to construct a starknet account which supports
/// hardware signers, webauthn, multisig, daily withdrawal limits and more.
#[starknet::contract(account)]
mod BraavosAccount {
    use braavos_account::account::interface::IBraavosAccountInternal;
    use array::{ArrayTrait, SpanTrait};
    use box::BoxTrait;
    use option::{Option, OptionTrait};
    use serde::Serde;
    use starknet::info::v2::ExecutionInfo;
    use starknet::{ClassHash, get_contract_address, get_tx_info, SyscallResultTrait, TxInfo};
    use starknet::syscalls::{call_contract_syscall, get_execution_info_v2_syscall,};
    use starknet::account::Call;
    use traits::{Into, TryInto};

    use braavos_account::account::interface;
    use braavos_account::dwl::dwl::DwlComponent;
    use braavos_account::dwl::interface::{BypassCallType, BypassRange};
    use braavos_account::introspection::src5::SRC5Component;
    use braavos_account::signers::signers::{
        Secp256r1PubKey, Secp256r1SignerMethodsTrait, StarkPubKey, StarkSignerMethodsTrait,
    };
    use braavos_account::signers::multisig::MultisigComponent;
    use braavos_account::signers::signer_management::{
        SignerManagementComponent, SIG_LEN_STARK, PUBLIC_KEY_LEN_SECP256R1, RS_LEN_SECP256R1
    };
    use braavos_account::signers::signer_type::{
        SignerType, EMPTY_SIGNER_TYPE, SECP256R1_SIGNER_TYPE, STARK_SIGNER_TYPE,
        WEBAUTHN_SIGNER_TYPE
    };
    use braavos_account::signers::signer_address_mgt::{get_first_signer, any, any_strong_signer};
    use braavos_account::upgradable::upgradable::UpgradableComponent;
    use braavos_account::utils::asserts::assert_self_caller;
    use braavos_account::outside_execution::outside_execution::OutsideExecComponent;

    mod Errors {
        const ALREADY_INITIALIZED: felt252 = 'ALREADY_INITIALIZED';
        const INVALID_ENTRYPOINT: felt252 = 'INVALID_ENTRYPOINT';
        const INVALID_SIG: felt252 = 'INVALID_SIG';
        const INVALID_SIGNER: felt252 = 'INVALID_SIGNER';
        const INVALID_SIGNER_TYPE: felt252 = 'INVALID_SIGNER_TYPE';
        const INVALID_TX_VERSION: felt252 = 'INVALID_TX_VERSION';
        const NO_DIRECT_DEPLOY: felt252 = 'NO_DIRECT_DEPLOY';
        const NO_REENTRANCE: felt252 = 'NO_REENTRANCE';
        const INVALID_TX: felt252 = 'INVALID_TX';
    }

    mod Consts {
        const L1_GAS_RESOURCE: felt252 = 'L1_GAS';
        const L2_GAS_RESOURCE: felt252 = 'L2_GAS';
        // 0.015 ETH
        const MAX_ETD_FEE_V1: u256 = 15000000000000000;
        // 100 STRK
        const MAX_ETD_FEE_V3: u256 = 100000000000000000000;
    }


    component!(path: DwlComponent, storage: dwl, event: DwlEvent);
    #[abi(embed_v0)]
    impl DwlExternalImpl = DwlComponent::DwlExternalImpl<ContractState>;
    impl DwlInternalImpl = DwlComponent::DwlInternalImpl<ContractState>;

    use braavos_account::dwl::rate_service::RateComponent;
    component!(path: RateComponent, storage: rate, event: RateEvent);
    #[abi(embed_v0)]
    impl RateConfigImpl = RateComponent::RateConfigImpl<ContractState>;
    impl RateServiceInternal = RateComponent::RateServiceInternalImpl<ContractState>;

    // Signers
    component!(path: SignerManagementComponent, storage: signers, event: SignerMgtEvt);
    #[abi(embed_v0)]
    impl SignerManagementImpl =
        SignerManagementComponent::SignerManagementImpl<ContractState>;
    impl SignerManagementImplInternal =
        SignerManagementComponent::SignerManagementImplInternal<ContractState>;

    // Multisig
    component!(path: MultisigComponent, storage: multisig, event: MultisigEvt);
    #[abi(embed_v0)]
    impl MultisigImpl = MultisigComponent::MultisigImpl<ContractState>;
    impl MultisigImplInternal = MultisigComponent::MultisigImplInternal<ContractState>;

    // Upgradable
    component!(path: UpgradableComponent, storage: upgradable, event: UpgradableEvt);
    #[abi(embed_v0)]
    impl UpgradableImpl = UpgradableComponent::UpgradableImpl<ContractState>;
    #[abi(embed_v0)]
    impl StorageMigrationImpl =
        UpgradableComponent::StorageMigrationImpl<ContractState>;

    // Introspection
    component!(path: SRC5Component, storage: src5, event: Src5Evt);
    #[abi(embed_v0)]
    impl SRC5Impl = SRC5Component::SRC5Impl<ContractState>;

    // Outside Execution
    component!(path: OutsideExecComponent, storage: outside_exec, event: OutsideExecEvt);
    #[abi(embed_v0)]
    impl OutsideExecImpl = OutsideExecComponent::OutsideExecImpl<ContractState>;

    /// ProcessedDeploymentSignature represents a parsed deployment signature
    /// @param signature - stark signed sig
    /// @param account_implementation - chash of the account we're deploying
    /// @param signer_type - type of strong signer which can be added during init
    /// @param secp256r1_signer - pub key of the strong signer
    /// @param multisig_threshold - requested multisig threshold
    /// @param withdrawal_limit_low
    /// If hte given transaction turns out not to be a legitmate dwl
    /// If hte given transaction turns out not to be a legitmate dwl
    /// @param fee_rate - if dwl limit is set, eth fee rate must be attached
    /// @param stark_fee_rate - if dwl limit is set, stark fee rate must be attached
    #[derive(Copy, Drop)]
    struct ProcessedDeploymentSignature {
        signature: (@felt252, @felt252),
        account_implementation: ClassHash,
        signer_type: usize,
        secp256r1_signer: Secp256r1PubKey,
        multisig_threshold: usize,
        withdrawal_limit_low: u128,
        fee_rate: u128,
        stark_fee_rate: u128,
    }

    impl ProcessedDeploymentSigSerde of Serde<ProcessedDeploymentSignature> {
        fn serialize(self: @ProcessedDeploymentSignature, ref output: Array<felt252>) {
            panic_with_felt252('NOT_IMPLEMENTED');
        }

        fn deserialize(ref serialized: Span<felt252>) -> Option<ProcessedDeploymentSignature> {
            let signer_type = (*serialized.at(3)).try_into().unwrap();
            assert(
                signer_type == EMPTY_SIGNER_TYPE
                    || signer_type == SECP256R1_SIGNER_TYPE
                    || signer_type == WEBAUTHN_SIGNER_TYPE,
                Errors::INVALID_SIGNER_TYPE
            );
            Option::Some(
                ProcessedDeploymentSignature {
                    signature: (serialized.at(0), serialized.at(1)),
                    account_implementation: (*serialized.at(2)).try_into().unwrap(),
                    signer_type: signer_type.try_into().unwrap(),
                    secp256r1_signer: Secp256r1PubKey {
                        pub_x: u256 {
                            low: (*serialized.at(4)).try_into().unwrap(),
                            high: (*serialized.at(5)).try_into().unwrap()
                        },
                        pub_y: u256 {
                            low: (*serialized.at(6)).try_into().unwrap(),
                            high: (*serialized.at(7)).try_into().unwrap()
                        },
                    },
                    multisig_threshold: (*serialized.at(8)).try_into().unwrap(),
                    withdrawal_limit_low: (*serialized.at(9)).try_into().unwrap(),
                    fee_rate: (*serialized.at(10)).try_into().unwrap(),
                    stark_fee_rate: (*serialized.at(11)).try_into().unwrap(),
                }
            )
        }
    }

    /// ProcessedSignature - represents a parsed transaction signature.
    /// A transaction signature can contain any number of signatures.
    /// @param num represents the number of validated signatures
    /// @param stark_validated whether one of the validated signatures was a stark signature
    /// @param secp256r1_validated whether one of the validated signatures was a hws signature
    /// @param webauthn_validated whether one of the validated signatures was a webauthn signature
    #[derive(Copy, Drop)]
    struct ProcessedSignature {
        num: u8,
        stark_validated: bool,
        secp256r1_validated: bool,
        webauthn_validated: bool,
    }

    #[generate_trait]
    impl ProcessedSignatureMethods of ProcessedSignatureMethodsTrait {
        fn is_any_strong_signature_validated(self: @ProcessedSignature) -> bool {
            *self.secp256r1_validated || *self.webauthn_validated
        }

        fn is_any_signature_validated(self: @ProcessedSignature) -> bool {
            *self.stark_validated || *self.secp256r1_validated || *self.webauthn_validated
        }
    }


    /// Helper function that fetches the fee and tx version from exec info. Fee calculation 
    /// depends on tx version. 
    /// for v1 we take the max_info value
    /// for v3 we return (L1_max_amount * L1_max_price_per_unit) + L2_max_amount * (L2_max_price_per_unit + tip)
    fn _extract_fee_from_tx(tx_info: @TxInfo, version: u256) -> u256 {
        if version.low == 1 {
            return (*tx_info.max_fee).into();
        } else if version.low == 3 {
            assert((*tx_info.resource_bounds).len() == 2, Errors::INVALID_TX);
            let first_item = (*tx_info.resource_bounds).at(0);
            let second_item = (*tx_info.resource_bounds).at(1);
            let (l1_gas, l2_gas) = if first_item.resource == @Consts::L1_GAS_RESOURCE {
                (first_item, second_item)
            } else {
                (second_item, first_item)
            };
            assert(l1_gas.resource == @Consts::L1_GAS_RESOURCE, Errors::INVALID_TX);
            assert(l2_gas.resource == @Consts::L2_GAS_RESOURCE, Errors::INVALID_TX);
            let l1_amount: u256 = (*l1_gas.max_amount).into();
            let l1_max_price_per_unit: u256 = (*l1_gas.max_price_per_unit).into();
            let l2_amount: u256 = (*l2_gas.max_amount).into();
            let l2_max_price_per_unit: u256 = (*l2_gas.max_price_per_unit).into();

            let l1_fee = l1_amount * l1_max_price_per_unit;
            let l2_fee = l2_amount * (l2_max_price_per_unit + (*tx_info.tip).into());
            return l1_fee + l2_fee;
        } else {
            panic_with_felt252(Errors::INVALID_TX);
            0
        }
    }


    #[storage]
    struct Storage {
        #[substorage(v0)]
        signers: SignerManagementComponent::Storage,
        #[substorage(v0)]
        multisig: MultisigComponent::Storage,
        #[substorage(v0)]
        upgradable: UpgradableComponent::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
        #[substorage(v0)]
        dwl: DwlComponent::Storage,
        #[substorage(v0)]
        rate: RateComponent::Storage,
        #[substorage(v0)]
        outside_exec: OutsideExecComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        SignerMgtEvt: SignerManagementComponent::Event,
        #[flat]
        MultisigEvt: MultisigComponent::Event,
        #[flat]
        UpgradableEvt: UpgradableComponent::Event,
        #[flat]
        Src5Evt: SRC5Component::Event,
        #[flat]
        DwlEvent: DwlComponent::Event,
        #[flat]
        RateEvent: RateComponent::Event,
        #[flat]
        OutsideExecEvt: OutsideExecComponent::Event
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
        panic_with_felt252(Errors::NO_DIRECT_DEPLOY);
    }

    /// This function is responsible for parsing the incoming transaction signature
    /// @param hash - The transaction hash
    /// @param signature - The transaction signature. This felt array may contain an untilimited
    /// list of signatures of different types. The input structure is
    /// [signature-type: felt252, signature-type-input, ....]. The length of the signature input
    /// is deduced from the signature type. This function also supports a standard (r, s) format
    /// @verify_signature - a flag indicating whether we should actually verify the signature
    /// or assume it is valid. This is used when estimating fee and when repeating this call
    /// during the execute stage validation of a dwl transaction. In the latter case we assume
    /// this function ran properly during the validate stage and there's no reason to repeat
    /// the expensive parts.
    fn _validate_signature_common(
        self: @ContractState, hash: felt252, signature: Span<felt252>, verify_signature: bool,
    ) -> ProcessedSignature {
        let sig_len = signature.len();

        assert(sig_len >= SIG_LEN_STARK, Errors::INVALID_SIG);
        // handle standard (r,s) format for tooling / sdk compatibility in default stark signer mode
        if sig_len == SIG_LEN_STARK {
            if verify_signature {
                let stark_signer = StarkPubKey { pub_key: get_first_signer(SignerType::Stark) };
                assert(stark_signer.validate_signature(hash, signature), Errors::INVALID_SIG);
            }

            return ProcessedSignature {
                num: 1_u8,
                stark_validated: true,
                secp256r1_validated: false,
                webauthn_validated: false
            };
        }

        let mut result = ProcessedSignature {
            num: 0_u8, stark_validated: false, secp256r1_validated: false, webauthn_validated: false
        };
        let mut duplicate_tracker: Felt252Dict<u8> = Default::default();
        let mut current_guid = 0;
        let mut offset = 0;
        loop {
            if offset >= sig_len {
                break;
            }

            let signer_type = signature.at(offset);
            offset = offset + 1;
            if signer_type == @STARK_SIGNER_TYPE {
                if verify_signature {
                    let stark_signer = StarkPubKey { pub_key: get_first_signer(SignerType::Stark) };
                    current_guid = stark_signer.guid();
                    assert(
                        stark_signer
                            .validate_signature(hash, signature.slice(offset, SIG_LEN_STARK)),
                        Errors::INVALID_SIG
                    );
                }

                result.num += 1;
                result.stark_validated = true;

                offset = offset + SIG_LEN_STARK;
            } else if signer_type == @SECP256R1_SIGNER_TYPE {
                if verify_signature {
                    let mut secp256r1_public_key = signature
                        .slice(offset, PUBLIC_KEY_LEN_SECP256R1);
                    let secp256r1_signer = Serde::<
                        Secp256r1PubKey
                    >::deserialize(ref secp256r1_public_key)
                        .expect(Errors::INVALID_SIGNER);
                    current_guid = secp256r1_signer
                        .exists(SignerType::Secp256r1)
                        .expect(Errors::INVALID_SIGNER);
                    let secp256r1_signature = signature
                        .slice(offset + PUBLIC_KEY_LEN_SECP256R1, RS_LEN_SECP256R1);
                    assert(
                        secp256r1_signer.validate_signature(hash, secp256r1_signature),
                        Errors::INVALID_SIG
                    );
                }

                result.num = result.num + 1;
                result.secp256r1_validated = true;

                offset = offset + PUBLIC_KEY_LEN_SECP256R1 + RS_LEN_SECP256R1;
            } else if signer_type == @WEBAUTHN_SIGNER_TYPE {
                let sig_offset: u32 = (offset + PUBLIC_KEY_LEN_SECP256R1).try_into().unwrap();
                let authdata_len: u32 = (*signature.at(sig_offset)).try_into().unwrap();
                let cdata_len: u32 = (*signature.at(sig_offset + authdata_len + 2))
                    .try_into()
                    .unwrap();
                // [ len(auth_data), *authdata, authdata_padding, len(cdata), *cdata, client_data_u32s_padding,
                //    challenge_offset, challenge_len, base64_padding, *sig, force_cairo_impl ]
                let sig_len = (1 + authdata_len + 2 + cdata_len + 4 + RS_LEN_SECP256R1 + 1);

                if verify_signature {
                    let mut secp256r1_public_key = signature
                        .slice(offset, PUBLIC_KEY_LEN_SECP256R1);
                    let secp256r1_signer = Serde::<
                        Secp256r1PubKey
                    >::deserialize(ref secp256r1_public_key)
                        .expect(Errors::INVALID_SIGNER);
                    current_guid = secp256r1_signer
                        .exists(SignerType::Webauthn)
                        .expect(Errors::INVALID_SIGNER);
                    let secp256r1_signature = signature
                        .slice(offset + PUBLIC_KEY_LEN_SECP256R1, sig_len);
                    assert(
                        secp256r1_signer.validate_webauthn_signature(hash, secp256r1_signature),
                        Errors::INVALID_SIG
                    );
                }

                result.num = result.num + 1;
                result.webauthn_validated = true;

                offset = offset + PUBLIC_KEY_LEN_SECP256R1 + sig_len;
            } else {
                panic_with_felt252(Errors::INVALID_SIGNER);
            };

            if verify_signature {
                assert(duplicate_tracker.get(current_guid) == 0, Errors::INVALID_SIG);
                duplicate_tracker.insert(current_guid, 1);
            };
        };
        return result;
    }

    /// This function is responsible to process a parsed signature according to the account rules.
    /// @param processed_sig - The parsed signature.
    /// @param is_etd_selector - A user can sign a deferred removal request of his strong signers
    /// incase he lost access to them using only a stark signer. This function allows a stark
    /// signer to bypass the rules here only in this particular case.
    /// @param block_timestamp - block timestamp
    fn _validate_processed_signature(
        self: @ContractState,
        processed_sig: ProcessedSignature,
        is_etd_selector: bool,
        block_timestamp: u64
    ) -> felt252 {
        let defered_remove_signer_req = self.signers.deferred_remove_signer_req.read();
        let is_secp256r1_present = any(SignerType::Secp256r1);
        let is_webauthn_present = any(SignerType::Webauthn);
        // Note: __validate__ applies and removes all expired deferred requests
        // The check here serves the is_valid_signature flow which cannot remove
        // deferred request since it is a view function. The checks simulates what
        // would happen if the request was removed
        let is_strong_signer_expected = (is_secp256r1_present || is_webauthn_present)
            && !SignerManagementComponent::_is_deferred_req_expired(
                defered_remove_signer_req, block_timestamp
            );
        if (is_strong_signer_expected) {
            if is_etd_selector {
                assert(
                    processed_sig.stark_validated == true
                        && processed_sig.is_any_strong_signature_validated() == false,
                    Errors::INVALID_SIG
                );
                // cover: fail if etd already pending
                assert(defered_remove_signer_req.expire_at == 0, Errors::INVALID_ENTRYPOINT);
                return starknet::VALIDATED;
            }

            // cover: multisig_thresh_must_be_0_or_2
            let multisig_thresh: usize = self.multisig.multisig_threshold.read();
            if multisig_thresh >= 2 {
                // cover: fail_single_signer_in_multisig
                // cover: fail_same_signer_in_multisig
                if (is_secp256r1_present && is_webauthn_present) {
                    assert(
                        processed_sig.num.into() >= multisig_thresh
                            && processed_sig.secp256r1_validated == true
                            && processed_sig.webauthn_validated == true,
                        Errors::INVALID_SIG
                    );
                } else {
                    assert(
                        processed_sig.num.into() >= multisig_thresh
                            && processed_sig.stark_validated == true
                            && processed_sig.is_any_strong_signature_validated() == true,
                        Errors::INVALID_SIG
                    );
                }
                return starknet::VALIDATED;
            } else {
                assert(
                    processed_sig.num == 1
                        && processed_sig.is_any_strong_signature_validated() == true
                        && processed_sig.stark_validated == false,
                    Errors::INVALID_SIG
                );
                return starknet::VALIDATED;
            }
        }
        assert(
            processed_sig.num == 1
                && processed_sig.stark_validated == true
                && processed_sig.is_any_strong_signature_validated() == false,
            Errors::INVALID_SIG
        );
        return starknet::VALIDATED;
    }

    /// This function returns true if the call array is indeed a deferred removal request.
    /// @param calls - list of calls, a legal deferred removal transaction contains a single call
    /// to the deferred removal selector.
    fn _assert_valid_etd_call(
        calls: Span<Call>, fee: u256, version: u256, paymaster_data: Span<felt252>
    ) -> bool {
        let call_0 = calls.at(0);
        let self_address = get_contract_address();
        let etd_selector = (calls.len() == 1
            && *call_0.to == self_address
            && *call_0
                .selector == SignerManagementComponent::Consts::DEFERRED_REMOVE_SECP256R1_SIGNERS_SELECTOR);

        if etd_selector {
            assert((*call_0.calldata).len() == 0, Errors::INVALID_ENTRYPOINT);
            // ETD calls are not allowed in a paymaster enabled mode
            // A user will have to send funds into the account
            assert(paymaster_data.len() == 0, Errors::INVALID_TX);
            assert(
                (version.low == 1 && fee <= Consts::MAX_ETD_FEE_V1)
                    || (version.low == 3 && fee <= Consts::MAX_ETD_FEE_V3),
                Errors::INVALID_TX
            );
        }
        return etd_selector;
    }

    #[abi(embed_v0)]
    impl ExternalMethods of interface::IBraavosAccount<ContractState> {
        /// get_version returns the current version of the account
        fn get_version(self: @ContractState) -> felt252 {
            super::ACCOUNT_VERSION
        }

        /// This function is responsible to initialize the account during construction.
        /// @param stark_pub_key - This account's stark signer public key
        /// @param signature - The signature contains several parameters that affect
        /// initialization. Parsing this signature is done in ProcessedDeploymentSigSerde.
        /// After parsing the signature the various components are being called with the input.
        fn initializer(ref self: ContractState, stark_pub_key: StarkPubKey) {
            assert(get_first_signer(SignerType::Stark) == 0, Errors::ALREADY_INITIALIZED);
            assert(stark_pub_key.pub_key.is_zero() == false, Errors::INVALID_SIGNER);
            let tx_info = get_tx_info().unbox();
            let mut signature = tx_info.signature;
            let processed_depl_sig = ProcessedDeploymentSigSerde::deserialize(ref signature)
                .unwrap();
            let mut num_signers = 1;
            self.signers._add_stark_signer_unsafe(stark_pub_key);
            if (processed_depl_sig.signer_type.into() != EMPTY_SIGNER_TYPE) {
                assert(
                    Secp256r1SignerMethodsTrait::assert_valid_point(
                        @processed_depl_sig.secp256r1_signer
                    ),
                    Errors::INVALID_SIGNER
                );

                self
                    .signers
                    ._add_secp256r1_signer_unsafe(
                        processed_depl_sig.secp256r1_signer,
                        Into::<u32, felt252>::into(processed_depl_sig.signer_type)
                            .try_into()
                            .unwrap(),
                    );

                num_signers += 1;
            }

            if (processed_depl_sig.multisig_threshold != 0) {
                self
                    .multisig
                    ._set_multisig_threshold_inner(
                        processed_depl_sig.multisig_threshold, num_signers
                    );
            }

            if (processed_depl_sig.withdrawal_limit_low != 0) {
                self
                    .dwl
                    ._set_withdrawal_limit_low_inner(
                        processed_depl_sig.withdrawal_limit_low,
                        processed_depl_sig.fee_rate,
                        processed_depl_sig.stark_fee_rate,
                        any_strong_signer()
                    );
            }
        }

        /// Starknet account standard execute function. This function iterates over the given
        /// calls, executes them and eventually returns the result.
        /// Before performing the calls this function performs the second validation step in
        /// _panic_on_bad_bypass_calls when withdrawal limits are set.
        fn __execute__(ref self: ContractState, mut calls: Span<Call>) -> Array<Span<felt252>> {
            let execution_info = get_execution_info_v2_syscall().unwrap_syscall().unbox();
            assert(execution_info.caller_address.is_zero(), Errors::NO_REENTRANCE);
            let tx_info = execution_info.tx_info.unbox();
            assert(tx_info.version != 0, Errors::INVALID_TX_VERSION);
            let block_timestamp = execution_info.block_info.unbox().block_timestamp;

            let dwl_status_pre_execute = self
                .dwl
                ._handle_bypass_calls_pre_execute(calls, block_timestamp);

            let res = self._execute_calls(calls, tx_info.transaction_hash, tx_info.signature);

            // If the account has no dwl set, or the calls are not valid bypass calls
            // then we are done. Otherwise this is a dwl compliant call and we need
            // to verify that spending is correct.
            if dwl_status_pre_execute.bypass_call_type != BypassCallType::NoDwl {
                let processed_sig = _validate_signature_common(
                    @self, tx_info.transaction_hash, tx_info.signature, false
                );
                let version = Into::<felt252, u256>::into(tx_info.version);
                let fee = _extract_fee_from_tx(@tx_info, version);
                let dwl_status_post_execute = self
                    .dwl
                    ._handle_bypass_calls_post_execute(
                        dwl_status_pre_execute,
                        block_timestamp,
                        processed_sig.stark_validated,
                        processed_sig.is_any_strong_signature_validated(),
                        processed_sig.num,
                        self.multisig.get_multisig_threshold(),
                        fee,
                        version.low.into()
                    );

                // If the status post execute is not a bypass call, meaning we've passed
                // the high range then we should validate the processed sig. An exception
                // for this is when the range on validate was already high, which means
                // the sig was validated in __validate__
                if dwl_status_post_execute == BypassCallType::NotBypassCall
                    && dwl_status_pre_execute.range_on_validate != BypassRange::HighRange {
                    if _validate_processed_signature(
                        @self,
                        processed_sig,
                        _assert_valid_etd_call(calls, fee, version, tx_info.paymaster_data),
                        block_timestamp
                    ) != starknet::VALIDATED {
                        panic_with_felt252(Errors::INVALID_SIG);
                    }
                }
            }

            return res;
        }

        /// Starknet account standard validate function. This function parses the incoming
        /// signature and decides whether this function should be executed.
        /// First part is to apply any expired deferred signer removal requests in _apply_deferred_remove_signers_req
        /// After that the signature is parsed in _validate_signature_common.
        /// Then we check whether this is a possible bypass call where we can use a weaker signer
        /// in _handle_bypass_calls_on_validate. The final validation would occur in __execute__.
        /// Finally the processed signature is validated according to the signers defined in account.
        fn __validate__(ref self: ContractState, calls: Span<Call>) -> felt252 {
            let exec_info = get_execution_info_v2_syscall().unwrap_syscall().unbox();
            assert(exec_info.caller_address.is_zero(), Errors::NO_REENTRANCE);
            let tx_info = exec_info.tx_info.unbox();
            let tx_hash = tx_info.transaction_hash;
            let signature = tx_info.signature;
            let block_timestamp = exec_info.block_info.unbox().block_timestamp;
            self.signers._apply_deferred_remove_signers_req(block_timestamp);

            let version = Into::<felt252, u256>::into(tx_info.version);
            let is_query_txn_ver = version.high == 1;
            let processed_sig = _validate_signature_common(
                @self, tx_hash, signature, !is_query_txn_ver
            );
            // also asserts that the etd call is valid meaning we will REJECT in __validate__
            let fee = _extract_fee_from_tx(@tx_info, version);
            let is_etd_selector = _assert_valid_etd_call(
                calls, fee, version, tx_info.paymaster_data
            );

            let bypass_range = self
                .dwl
                ._handle_bypass_calls_on_validate(block_timestamp, calls, fee, version.low.into());
            // checking that at least some signature is verified otherwise anyone can start draining
            if bypass_range == BypassRange::LowerRange
                && processed_sig.is_any_signature_validated() {
                return starknet::VALIDATED;
            } else if bypass_range == BypassRange::MidRange
                && processed_sig.is_any_strong_signature_validated() {
                return starknet::VALIDATED;
            }

            _validate_processed_signature(@self, processed_sig, is_etd_selector, block_timestamp)
        }

        fn is_valid_signature(
            self: @ContractState, hash: felt252, signature: Span<felt252>
        ) -> felt252 {
            let exec_info = get_execution_info_v2_syscall().unwrap_syscall().unbox();
            let block_timestamp = exec_info.block_info.unbox().block_timestamp;
            let transaction_ver = exec_info.tx_info.unbox().version;
            self._is_valid_signature_common(hash, signature, block_timestamp, transaction_ver)
        }


        fn __validate_deploy__(
            self: @ContractState, class_hash: felt252, salt: felt252, stark_pub_key: StarkPubKey,
        ) -> felt252 {
            // This contract cannot be directly deployed (see constructor)
            // and actual deployment validation happens in base account in assert_valid_deploy_base
            // (see braavos_base_account)
            starknet::VALIDATED
        }

        fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
            let exec_info = get_execution_info_v2_syscall().unwrap_syscall().unbox();
            let tx_info = exec_info.tx_info.unbox();
            let tx_hash = tx_info.transaction_hash;
            let signature = tx_info.signature;
            let block_timestamp = exec_info.block_info.unbox().block_timestamp;
            self._is_valid_signature_common(tx_hash, signature, block_timestamp, tx_info.version)
        }

        /// This function returns an enum that helps clients to assess which signer would be
        /// required for a particular transaction. The main factors affecting the decision
        /// is whether this is an etd call or a withdrawal limits call.
        /// The function is limited to simulation from self only
        /// @param calls - calls comprising the transaction client would like to send
        /// @param fee_amount - estimated fee the transaction would have
        /// @param tx_version - type of transaction, can be 1 or 3 at the moment
        fn get_required_signer(
            ref self: ContractState, calls: Span<Call>, fee_amount: u128, tx_version: felt252
        ) -> interface::RequiredSigner {
            assert_self_caller();
            let execution_info = get_execution_info_v2_syscall().unwrap_syscall().unbox();
            let tx_info = execution_info.tx_info.unbox();
            // Allow only simulation, no execution
            assert(
                Into::<felt252, u256>::into(tx_info.version).high == 1, Errors::INVALID_TX_VERSION
            );

            let block_timestamp = execution_info.block_info.unbox().block_timestamp;

            // tx version for getting the correct DWL signer (for fee calculation purposes)
            assert(tx_version == 1 || tx_version == 3, Errors::INVALID_TX_VERSION);

            self._apply_deferred_remove_signers_req(block_timestamp);

            if !any_strong_signer()
                || _assert_valid_etd_call(
                    calls, fee_amount.into(), tx_version.into(), array![].span()
                ) {
                return interface::RequiredSigner::Stark;
            }

            let range_on_validate = self
                .dwl
                ._handle_bypass_calls_on_validate(
                    block_timestamp, calls, fee_amount.into(), tx_version
                );
            if range_on_validate == BypassRange::NA {
                return self._get_signer_type_in_account();
            }
            if range_on_validate == BypassRange::HighRange {
                return self._get_signer_type_in_account();
            }

            let dwl_status_pre_execute = self
                .dwl
                ._handle_bypass_calls_pre_execute(calls, block_timestamp);

            self._execute_calls(calls, tx_info.transaction_hash, tx_info.signature);

            let (range, _, _, _) = self
                .dwl
                ._calc_and_update_daily_spending_post_execute(
                    dwl_status_pre_execute, block_timestamp, fee_amount.into(), tx_version,
                );

            if range == BypassRange::LowerRange {
                if range_on_validate == BypassRange::LowerRange {
                    return interface::RequiredSigner::Stark;
                } else {
                    return interface::RequiredSigner::Strong;
                }
            } else if range == BypassRange::MidRange {
                // Midrange implies that there is a high dwl thus multisig
                return interface::RequiredSigner::Strong;
            } else {
                return self._get_signer_type_in_account();
            }
        }
    }

    impl BraavosAccountInternalImpl of interface::IBraavosAccountInternal<ContractState> {
        fn _get_signer_type_in_account(self: @ContractState) -> interface::RequiredSigner {
            if self.multisig.get_multisig_threshold() > 1 {
                return interface::RequiredSigner::Multisig;
            } else if any_strong_signer() {
                return interface::RequiredSigner::Strong;
            } else {
                return interface::RequiredSigner::Stark;
            }
        }

        fn _is_valid_signature_common(
            self: @ContractState,
            hash: felt252,
            signature: Span<felt252>,
            block_timestamp: u64,
            transaction_ver: felt252,
        ) -> felt252 {
            let is_query_txn_ver = Into::<felt252, u256>::into(transaction_ver).high == 1;
            let processed_sig = _validate_signature_common(
                self, hash, signature, !is_query_txn_ver
            );

            _validate_processed_signature(self, processed_sig, false, block_timestamp)
        }

        fn _execute_calls(
            ref self: ContractState,
            mut calls: Span<Call>,
            tx_hash: felt252,
            signature: Span<felt252>
        ) -> Array<Span<felt252>> {
            let mut result = ArrayTrait::new();
            loop {
                match calls.pop_front() {
                    Option::Some(call) => {
                        let mut res = call_contract_syscall(
                            address: *call.to,
                            entry_point_selector: *call.selector,
                            calldata: *call.calldata
                        )
                            .unwrap_syscall();
                        result.append(res);
                    },
                    Option::None => { break; },
                };
            };
            result
        }
    }
}

