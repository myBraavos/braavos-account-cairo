#[starknet::component]
mod DwlComponent {
    use core::array::SpanTrait;
    use starknet::account::Call;
    use braavos_account::dwl::interface::{
        IDwlInternal, IDwlExternal, BypassCallType, BypassRange, IRateServiceInternal,
        PreExecuteBypassState, WhitelistCallType, MainnetConfig
    };
    use braavos_account::account::interface::RequiredSigner;
    use braavos_account::signers::interface::{IMultisig, ISignerManagement};
    use braavos_account::signers::signer_address_mgt::{any_strong_signer};
    use braavos_account::utils::asserts::assert_self_caller;
    use starknet::syscalls::get_execution_info_v2_syscall;
    use starknet::get_tx_info;
    use starknet::{SyscallResultTrait, ContractAddress,};
    use starknet::storage::Map;

    #[derive(Drop, starknet::Event)]
    struct WithdrawalLimitLowSet {
        withdrawal_limit_low: u128,
    }

    #[derive(Drop, starknet::Event)]
    struct WithdrawalLimitHighSet {
        withdrawal_limit_high: u128,
    }

    #[storage]
    struct Storage {
        withdrawal_limit_low: u128,
        withdrawal_limit_high: u128,
        daily_spending: Map<u64, u128>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        WithdrawalLimitLowSet: WithdrawalLimitLowSet,
        WithdrawalLimitHighSet: WithdrawalLimitHighSet,
    }

    mod Consts {
        const SECONDS_IN_DAY: u64 = 86400;
        const ETHER: u128 = 1000000000000000000;
        const HUNDRED_PERCENT: u128 = 100000;
        const RATE_UPDATE_THRESHOLD_PERCENT: u128 = 5000;
        const TRANSFER_CALL_SELECTOR: felt252 = selector!("transfer");
        const APPROVE_CALL_SELECTOR: felt252 = selector!("approve");
        const SWAP_CALL_SELECTOR: felt252 = selector!("swap");
        const TRANSFER_APPROVE_CALLDATA_LEN: u32 = 3;
    }

    mod Errors {
        const INVALID_HIGH_WITHDRAWAL_LIMIT: felt252 = 'INVALID_HIGH_WITHDRAWAL_LIMIT';
        const INVALID_WITHDRAWAL_LIMIT_LOW: felt252 = 'INVALID_WITHDRAWAL_LIMIT_LOW';
        const MISSING_FEE: felt252 = 'MISSING_FEE';
    }

    #[generate_trait]
    impl DwlUtilImpl of DwlUtilTrait {
        #[inline(always)]
        fn get_daily_spending_key(block_timestamp: u64) -> u64 {
            block_timestamp / Consts::SECONDS_IN_DAY
        }

        /// Helper function returning the type of signer required based on spend and existing
        /// threholds
        #[inline(always)]
        fn get_signer_by_dwl(
            withdrawal_limit_low: u128,
            withdrawal_limit_high: u128,
            daily_spend: u128,
            strongest_signer: RequiredSigner
        ) -> RequiredSigner {
            if Self::is_in_low_range(withdrawal_limit_low, daily_spend) {
                return RequiredSigner::Stark;
            } else if Self::is_in_mid_range(
                withdrawal_limit_low, withdrawal_limit_high, daily_spend
            ) {
                return RequiredSigner::Strong;
            }

            return strongest_signer;
        }

        /// Helper function returning true if spend is under the lower limit
        #[inline(always)]
        fn is_in_low_range(withdrawal_limit_low: u128, daily_spend: u128) -> bool {
            withdrawal_limit_low > 0 && daily_spend < withdrawal_limit_low
        }

        /// Helper function returning true if spend is between low limit and high limit
        /// If there is no low limit then daily spend may be just below the high limit
        /// High limit must exist.
        #[inline(always)]
        fn is_in_mid_range(
            withdrawal_limit_low: u128, withdrawal_limit_high: u128, daily_spend: u128
        ) -> bool {
            if withdrawal_limit_high == 0 {
                return false;
            }

            if withdrawal_limit_low > 0 {
                return daily_spend >= withdrawal_limit_low && daily_spend < withdrawal_limit_high;
            } else {
                return daily_spend < withdrawal_limit_high;
            }
        }

        /// Helper function which checks whether the inputs are more than 5% a part
        #[inline(always)]
        fn is_significant_fee_rate_change(existing_fee_rate: u128, new_fee_rate: u128) -> bool {
            if (new_fee_rate > existing_fee_rate && new_fee_rate
                - existing_fee_rate > existing_fee_rate
                    * Consts::RATE_UPDATE_THRESHOLD_PERCENT
                    / Consts::HUNDRED_PERCENT)
                || (new_fee_rate <= existing_fee_rate && existing_fee_rate
                    - new_fee_rate > existing_fee_rate
                        * Consts::RATE_UPDATE_THRESHOLD_PERCENT
                        / Consts::HUNDRED_PERCENT) {
                true
            } else {
                false
            }
        }
    }

    #[embeddable_as(DwlInternalImpl)]
    impl InternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        +IRateServiceInternal<TContractState>,
        +Drop<TContractState>,
    > of IDwlInternal<ComponentState<TContractState>> {
        /// Saves the new low limit threshold in storage. Verifies it is legal and that there
        /// are fee rates saved.
        fn _set_withdrawal_limit_high_inner(
            ref self: ComponentState<TContractState>,
            withdrawal_limit_high: u128,
            fee_rate: u128,
            stark_fee_rate: u128,
            any_strong_signer: bool,
            is_multisig: bool,
        ) {
            assert(
                withdrawal_limit_high == 0 || any_strong_signer,
                Errors::INVALID_HIGH_WITHDRAWAL_LIMIT
            );
            assert(
                withdrawal_limit_high == 0 || is_multisig, Errors::INVALID_HIGH_WITHDRAWAL_LIMIT
            );
            if withdrawal_limit_high != 0 {
                let withdrawal_limit_low: u128 = self.withdrawal_limit_low.read();
                assert(
                    withdrawal_limit_low == 0
                        || withdrawal_limit_low < withdrawal_limit_high.into(),
                    Errors::INVALID_HIGH_WITHDRAWAL_LIMIT
                );
                self._ensure_fee_rate_exists(fee_rate, stark_fee_rate);
            }

            self.emit(WithdrawalLimitHighSet { withdrawal_limit_high: withdrawal_limit_high });
            self.withdrawal_limit_high.write(withdrawal_limit_high);
        }

        /// Saves the new high limit threshold in storage. Verifies it is legal and that there
        /// are fee rates saved.
        fn _set_withdrawal_limit_low_inner(
            ref self: ComponentState<TContractState>,
            withdrawal_limit_low: u128,
            fee_rate: u128,
            stark_fee_rate: u128,
            any_strong_signer: bool,
        ) {
            assert(
                withdrawal_limit_low == 0 || any_strong_signer, Errors::INVALID_WITHDRAWAL_LIMIT_LOW
            );
            if withdrawal_limit_low != 0 {
                let withdrawal_limit_high: u128 = self.withdrawal_limit_high.read();
                assert(
                    withdrawal_limit_high == 0
                        || withdrawal_limit_high > withdrawal_limit_low.into(),
                    Errors::INVALID_WITHDRAWAL_LIMIT_LOW
                );
                self._ensure_fee_rate_exists(fee_rate, stark_fee_rate);
            }

            self.emit(WithdrawalLimitLowSet { withdrawal_limit_low: withdrawal_limit_low });
            self.withdrawal_limit_low.write(withdrawal_limit_low);
        }

        /// Fetches stored low threshold limit
        fn _get_withdrawal_limit_low_inner(self: @ComponentState<TContractState>) -> u128 {
            self.withdrawal_limit_low.read()
        }

        /// Fetches stored high threshold limit
        fn _get_withdrawal_limit_high_inner(self: @ComponentState<TContractState>) -> u128 {
            self.withdrawal_limit_high.read()
        }

        /// Updates the daily spend given the new fee rate. The daily spend was updated during
        /// the validate step with stored fee rate which might be stale. The previously added
        /// fee rate is removed and the new one is added.
        #[inline(always)]
        fn _update_fee_rate_and_adjust_daily_spending(
            ref self: ComponentState<TContractState>,
            mut daily_spend: u128,
            fee: u256,
            fee_rate: u128,
            is_stark_fee: bool,
            existing_fee_rate: u128,
        ) -> u128 {
            if DwlUtilImpl::is_significant_fee_rate_change(existing_fee_rate, fee_rate) {
                let mut mut_contract = self.get_contract_mut();
                if is_stark_fee {
                    mut_contract._set_stored_stark_fee_rate(fee_rate);
                } else {
                    mut_contract._set_stored_eth_fee_rate(fee_rate);
                }
            }

            daily_spend -= self.get_contract()._calc_fee_value_with_rate(existing_fee_rate, fee);
            daily_spend += self.get_contract()._calc_fee_value_with_rate(fee_rate, fee);
            daily_spend
        }

        /// Fails if no fee rates are defined in account and no fee rate input is given.
        /// Updates the stored fee rates based on the given input.
        #[inline(always)]
        fn _ensure_fee_rate_exists(
            ref self: ComponentState<TContractState>, fee_rate: u128, stark_fee_rate: u128
        ) {
            let existing_fee_rate: u128 = self.get_contract()._get_stored_eth_fee_rate();
            let existing_stark_fee_rate: u128 = self.get_contract()._get_stored_stark_fee_rate();

            if fee_rate == 0 {
                assert(existing_fee_rate > 0, Errors::MISSING_FEE);
            } else {
                let mut mut_contract = self.get_contract_mut();
                mut_contract._set_stored_eth_fee_rate(fee_rate);
            }

            if stark_fee_rate == 0 {
                assert(existing_stark_fee_rate > 0, Errors::MISSING_FEE);
            } else {
                let mut mut_contract = self.get_contract_mut();
                mut_contract._set_stored_stark_fee_rate(stark_fee_rate);
            }
        }

        /// Returns the bypass range of the current daily spending and transaction fee.
        /// Also adds the fee value to the daily spend. Fee is added at this point to
        /// prevent drainage attacks when dwl is set in an account and stark private key
        /// is compromised.
        fn _handle_bypass_calls_on_validate(
            ref self: ComponentState<TContractState>,
            block_timestamp: u64,
            calls: Span<Call>,
            fee: u256,
            version: felt252,
        ) -> BypassRange {
            let withdrawal_limit_low = self.withdrawal_limit_low.read();
            let withdrawal_limit_high = self.withdrawal_limit_high.read();
            if withdrawal_limit_low == 0 && withdrawal_limit_high == 0 {
                return BypassRange::NA;
            }
            if !self._validate_call_structure(calls) {
                return BypassRange::NA;
            }

            let contract = self.get_contract();
            let fee_value = contract._calc_fee_value_with_stored_rate_by_version(fee, version);
            let daily_spending_key = DwlUtilImpl::get_daily_spending_key(block_timestamp);
            let daily_spending: u128 = self.daily_spending.read(daily_spending_key);
            let updated_spending = daily_spending + fee_value;

            let is_mid_bypass_transfer = DwlUtilImpl::is_in_mid_range(
                withdrawal_limit_low, withdrawal_limit_high, updated_spending
            );
            let is_low_bypass_transfer = DwlUtilImpl::is_in_low_range(
                withdrawal_limit_low, updated_spending
            );

            // we update the fee in case this tx reverts during __execute__
            // otherwise this can be called indefinitely until tokens run out
            self.daily_spending.write(daily_spending_key, updated_spending);

            if is_low_bypass_transfer {
                BypassRange::LowerRange
            } else if is_mid_bypass_transfer {
                BypassRange::MidRange
            } else {
                BypassRange::HighRange
            }
        }

        /// This function is meant to run before executing calls in the __execute__ function
        /// If the input is a valid dwl call span then this function would return a report of
        /// the balances of all logged tokens.
        fn _handle_bypass_calls_pre_execute(
            ref self: ComponentState<TContractState>, calls: Span<Call>, block_timestamp: u64,
        ) -> PreExecuteBypassState {
            let withdrawal_limit_low = self.withdrawal_limit_low.read();
            let withdrawal_limit_high = self.withdrawal_limit_high.read();
            if withdrawal_limit_low == 0 && withdrawal_limit_high == 0 {
                return PreExecuteBypassState {
                    balances: array![].span(),
                    bypass_call_type: BypassCallType::NoDwl,
                    range_on_validate: BypassRange::HighRange
                };
            }

            if !self._validate_call_structure(calls) {
                return PreExecuteBypassState {
                    balances: array![].span(),
                    bypass_call_type: BypassCallType::NoDwl,
                    range_on_validate: BypassRange::HighRange
                };
            }

            let contract = self.get_contract();
            let balances = contract._get_balance_report();

            let daily_spending_key = DwlUtilImpl::get_daily_spending_key(block_timestamp);
            let daily_spending: u128 = self.daily_spending.read(daily_spending_key);

            let range_on_validate = if DwlUtilImpl::is_in_low_range(
                withdrawal_limit_low, daily_spending
            ) {
                BypassRange::LowerRange
            } else if DwlUtilImpl::is_in_mid_range(
                withdrawal_limit_low, withdrawal_limit_high, daily_spending
            ) {
                BypassRange::MidRange
            } else {
                BypassRange::HighRange
            };
            return PreExecuteBypassState {
                balances: balances,
                bypass_call_type: BypassCallType::ValidBypassCall,
                range_on_validate: range_on_validate
            };
        }

        /// This function calculates the final accurate daily spending. It analyzes
        /// the change in the balances of all whitelisted tokens and adjusts the fee spending to use
        /// the latest fee rate. It eventually returns the range in which the daily spending is
        /// in (low, mid, high), the accurate daily spending value which is later used to
        /// update the storage and what was stored so far
        fn _calc_and_update_daily_spending_post_execute(
            ref self: ComponentState<TContractState>,
            pre_execute_bypass_state: PreExecuteBypassState,
            block_timestamp: u64,
            fee: u256,
            version: felt252,
        ) -> (BypassRange, u128, u128, u128) {
            let contract = self.get_contract();

            let decrease_in_value = contract
                ._analyze_change_in_balance(pre_execute_bypass_state.balances);

            let daily_spending_key = DwlUtilImpl::get_daily_spending_key(block_timestamp);
            let stored_spending = self.daily_spending.read(daily_spending_key);
            let daily_spending = stored_spending + decrease_in_value;

            let fee_response = contract._analyze_fee(fee, version);
            let old_fee_rate: u128 = if fee_response.is_stark_fee {
                self.get_contract()._get_stored_stark_fee_rate()
            } else {
                self.get_contract()._get_stored_eth_fee_rate()
            };

            let daily_spend_with_updated_fee: u128 = self
                ._update_fee_rate_and_adjust_daily_spending(
                    daily_spending,
                    fee,
                    fee_response.fee_rate.try_into().unwrap(),
                    fee_response.is_stark_fee,
                    old_fee_rate,
                );

            let withdrawal_limit_low = self.withdrawal_limit_low.read();
            let withdrawal_limit_high = self.withdrawal_limit_high.read();
            let range = if DwlUtilImpl::is_in_low_range(
                withdrawal_limit_low, daily_spend_with_updated_fee
            ) {
                BypassRange::LowerRange
            } else if DwlUtilImpl::is_in_mid_range(
                withdrawal_limit_low, withdrawal_limit_high, daily_spend_with_updated_fee
            ) {
                BypassRange::MidRange
            } else {
                BypassRange::HighRange
            };
            return (range, daily_spend_with_updated_fee, stored_spending, old_fee_rate);
        }

        /// This function runs post call execute. It analyzes the difference in balances
        /// between now and before the calls were executed and sums up the changes and
        /// the accurate fee spent. It then checks whether there's a mtch between the bypass
        /// level of call and the present signers
        fn _handle_bypass_calls_post_execute(
            ref self: ComponentState<TContractState>,
            pre_execute_bypass_state: PreExecuteBypassState,
            block_timestamp: u64,
            stark_signer_validated: bool,
            strong_signer_validated: bool,
            signer_num: u8,
            multisig_threshold: u32,
            fee: u256,
            version: felt252,
        ) -> BypassCallType {
            if pre_execute_bypass_state.bypass_call_type == BypassCallType::NoDwl {
                return BypassCallType::NoDwl;
            }
            let (range, daily_spend_with_updated_fee, stored_spending, old_fee_rate) = self
                ._calc_and_update_daily_spending_post_execute(
                    pre_execute_bypass_state, block_timestamp, fee, version
                );
            let daily_spending_key = DwlUtilImpl::get_daily_spending_key(block_timestamp);
            // if were under limit low then an eligible bypass signer is either a stark signer
            // or a hws when the wallet has multisig turned on
            if range == BypassRange::LowerRange {
                if stark_signer_validated && signer_num == 1 {
                    self.daily_spending.write(daily_spending_key, daily_spend_with_updated_fee);
                    return BypassCallType::ValidBypassCall;
                } else if strong_signer_validated
                    && signer_num.into() < multisig_threshold
                    && multisig_threshold >= 2 {
                    self.daily_spending.write(daily_spending_key, daily_spend_with_updated_fee);
                    return BypassCallType::ValidBypassCall;
                }
            }

            // if we're between limit low and limit high then an eligible bypass signer is only
            // a hws
            if range == BypassRange::MidRange {
                if (strong_signer_validated && signer_num.into() < multisig_threshold) {
                    self.daily_spending.write(daily_spending_key, daily_spend_with_updated_fee);
                    return BypassCallType::ValidBypassCall;
                }
            }

            /// Reaching here means that while the call structure is that of a valid bypass call,
            /// the daily spending status does not match the processed signature or we are at the
            /// highest range. In both cases we would like to validate the signature fully like
            /// a non dwl transaction. Also we are deducting the fee spending added during the
            /// __validate__ phase
            self
                .daily_spending
                .write(
                    daily_spending_key,
                    stored_spending
                        - self.get_contract()._calc_fee_value_with_rate(old_fee_rate, fee)
                );

            return BypassCallType::NotBypassCall;
        }


        /// A valid single call must be a whitelisted token and have the structure of an approve
        /// or transfer.
        fn _validate_single_call_structure(
            self: @ComponentState<TContractState>,
            selector: felt252,
            to: ContractAddress,
            calldata: Span<felt252>,
            allowed_selector: felt252,
        ) -> bool {
            if selector == allowed_selector {
                if calldata.len() == Consts::TRANSFER_APPROVE_CALLDATA_LEN {
                    let token_config = self.get_contract()._get_token_config(to);
                    if token_config.is_threshold_currency || token_config.pool_key != 0 {
                        return true;
                    }
                }
            }
            return false;
        }

        /// This function validates a couplet of calls. The valid structure is one approve
        /// and then a whitelisted call. Theres also a mainnet hardcoded option for myswapcl.
        fn _validate_couplet_call_structure(
            self: @ComponentState<TContractState>, calls: Span<Call>,
        ) -> bool {
            let first_call = calls.at(0);
            let second_call = calls.at(1);
            let is_first_call_valid = self
                ._validate_single_call_structure(
                    *first_call.selector,
                    *first_call.to,
                    *first_call.calldata,
                    Consts::APPROVE_CALL_SELECTOR
                );
            let approve_to = (*first_call.calldata).at(0);
            // we validate that the first call is a valid approval
            // and that this approval is directed at the contract of the second call
            if is_first_call_valid && *approve_to == (*second_call.to).into() {
                let whitelist_type = self
                    .get_contract()
                    ._get_whitelist_call_type(*second_call.to, *second_call.selector);

                // if the type of whitelisted call, it means that there is no config
                // we therefor check whether this is the hardcoded myswapcl swap call
                if whitelist_type == WhitelistCallType::NA {
                    return (*second_call.to).into() == MainnetConfig::MYSWAP_CL_ADDRESS
                        && *second_call.selector == Consts::SWAP_CALL_SELECTOR;
                } else {
                    return whitelist_type == WhitelistCallType::OneApprove;
                }
            }

            return false;
        }

        /// This function validates a triplet of calls. The valid structure is two consecutive
        /// approves and then a valid white listed call.
        fn _validate_triplet_call_structure(
            self: @ComponentState<TContractState>, calls: Span<Call>,
        ) -> bool {
            let first_call = calls.at(0);
            let second_call = calls.at(1);
            let third_call = calls.at(2);
            let is_first_call_valid = self
                ._validate_single_call_structure(
                    *first_call.selector,
                    *first_call.to,
                    *first_call.calldata,
                    Consts::APPROVE_CALL_SELECTOR
                );
            let first_approve_to = (*first_call.calldata).at(0);
            // we validate that the first call is a valid approval
            // and that this approval is directed at the contract of the third call
            if is_first_call_valid && *first_approve_to == (*third_call.to).into() {
                let is_second_call_valid = self
                    ._validate_single_call_structure(
                        *second_call.selector,
                        *second_call.to,
                        *second_call.calldata,
                        Consts::APPROVE_CALL_SELECTOR
                    );
                let second_approve_to = (*second_call.calldata).at(0);
                // we validate that the second call is also a valid approval
                // and that this approval is directed at the contract of the third call
                // we also validate that the two approves don't approve the same token
                if is_second_call_valid
                    && *first_call.to != *second_call.to
                    && *second_approve_to == (*third_call.to).into() {
                    let whitelist_call_type = self
                        .get_contract()
                        ._get_whitelist_call_type(*third_call.to, *third_call.selector);
                    return whitelist_call_type == WhitelistCallType::TwoApproves;
                }
            }

            return false;
        }

        /// This function validates the dwl structure of a call span. A valid dwl call structure
        /// is either of length 1, 2 or 3. A call span with length 1 must only contain a valid
        /// transfer call to a whitelisted token. A call span with length 2 must only contain
        /// an approve call as the first call, and a call to whitelisted call in the second call.
        /// A call span with length 3 must have two consecutive approves in the first two calls
        /// and then a whitelisted call in the the third call
        fn _validate_call_structure(
            self: @ComponentState<TContractState>, calls: Span<Call>
        ) -> bool {
            let tx_info = get_tx_info().unbox();
            // DWL calls are not allowed in a paymaster mode
            if tx_info.paymaster_data.len() != 0 {
                return false;
            }

            match calls.len() {
                0 => { return false; },
                1 => {
                    let call = calls.at(0);
                    return self
                        ._validate_single_call_structure(
                            *call.selector, *call.to, *call.calldata, Consts::TRANSFER_CALL_SELECTOR
                        );
                },
                2 => { return self._validate_couplet_call_structure(calls); },
                3 => { return self._validate_triplet_call_structure(calls); },
                _ => { return false; }
            }
        }
    }

    #[embeddable_as(DwlExternalImpl)]
    impl ExternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        +ISignerManagement<TContractState>,
        +IMultisig<TContractState>,
        +IRateServiceInternal<TContractState>,
        +Drop<TContractState>,
    > of IDwlExternal<ComponentState<TContractState>> {
        /// Sets the lower withdrawal limit using eth and stark rates fetched from price service
        fn set_withdrawal_limit_low(
            ref self: ComponentState<TContractState>, withdrawal_limit_low: u128,
        ) {
            assert_self_caller();
            let fee_rate = self.get_contract()._get_eth_fee_rate();
            let stark_fee_rate = self.get_contract()._get_stark_fee_rate();
            self
                ._set_withdrawal_limit_low_inner(
                    withdrawal_limit_low, fee_rate, stark_fee_rate, any_strong_signer()
                );
        }

        /// Sets the higher withdrawal limit using eth and stark rates fetched from price service
        fn set_withdrawal_limit_high(
            ref self: ComponentState<TContractState>, withdrawal_limit_high: u128,
        ) {
            assert_self_caller();
            let fee_rate = self.get_contract()._get_eth_fee_rate();
            let stark_fee_rate = self.get_contract()._get_stark_fee_rate();
            self
                ._set_withdrawal_limit_high_inner(
                    withdrawal_limit_high,
                    fee_rate,
                    stark_fee_rate,
                    any_strong_signer(),
                    self.get_contract().get_multisig_threshold() >= 2
                );
        }

        /// Fetches current low withdrawal limit
        fn get_withdrawal_limit_low(self: @ComponentState<TContractState>) -> u128 {
            self.withdrawal_limit_low.read()
        }

        /// Fetches current high withdrawal limit
        fn get_withdrawal_limit_high(self: @ComponentState<TContractState>) -> u128 {
            self.withdrawal_limit_high.read()
        }

        /// Fetches the current daily spending in the units of the currency used as a
        /// threshold currency.
        fn get_daily_spend(self: @ComponentState<TContractState>) -> u128 {
            let execution_info = get_execution_info_v2_syscall().unwrap_syscall().unbox();
            let block_timestamp = execution_info.block_info.unbox().block_timestamp;
            self.daily_spending.read(DwlUtilImpl::get_daily_spending_key(block_timestamp))
        }

        /// Fetches current stored fee rate for eth
        fn get_fee_token_rate(self: @ComponentState<TContractState>) -> u128 {
            self.get_contract()._get_stored_eth_fee_rate()
        }

        /// Fetches current stored fee rate for stark
        fn get_stark_fee_token_rate(self: @ComponentState<TContractState>) -> u128 {
            self.get_contract()._get_stored_stark_fee_rate()
        }
    }
}
