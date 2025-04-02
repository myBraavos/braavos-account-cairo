use starknet::ContractAddress;

/// Provides an average price for specified period
#[starknet::interface]
trait IPoolPrice<TState> {
    fn get_average_price(self: @TState, pool_key: felt252, seconds_ago: u32) -> u256;
}

#[starknet::interface]
trait IERC20BalanceOf<TState> {
    fn balanceOf(self: @TState, owner: ContractAddress) -> u256;
}


#[starknet::component]
mod RateComponent {
    use braavos_account::dwl::interface::{
        FeeInfoResponse, IRateServiceExternal, IRateServiceInternal, MainnetConfig, TokenConfig,
        TransferInfoResponse, WhitelistCallConfig, WhitelistCallType,
    };
    use braavos_account::utils::asserts::assert_self_caller;
    use braavos_account::utils::utils::mulDiv;
    use core::array::{ArrayTrait, SpanTrait};
    use core::option::OptionTrait;
    use core::traits::{Into, TryInto};
    use dict::Felt252DictTrait;
    use starknet::storage::Map;
    use starknet::{
        ContractAddress, ContractAddressIntoFelt252, Felt252TryIntoContractAddress,
        SyscallResultTrait, get_contract_address,
    };
    use super::{
        IERC20BalanceOf, IERC20BalanceOfDispatcher, IERC20BalanceOfDispatcherTrait, IPoolPrice,
        IPoolPriceDispatcher, IPoolPriceDispatcherTrait,
    };

    #[storage]
    struct Storage {
        white_listed_tokens_map: Map<ContractAddress, TokenConfig>,
        white_listed_custom_list: Map<u8, ContractAddress>,
        white_listed_custom_list_length: u8,
        white_listed_contracts_and_selectors: Map<(ContractAddress, felt252), WhitelistCallType>,
        fee_token: TokenConfig,
        stark_fee_token: TokenConfig,
        stored_fee_rate_eth: u128,
        stored_fee_rate_stark: u128,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {}


    mod Consts {
        const ETHER: u256 = 1000000000000000000;
        const X96: u256 = 0x1000000000000000000000000;
        const DAY_SEC: u32 = 86400_u32;
    }

    mod Errors {
        const INVALID_PRICE: felt252 = 'INVALID_PRICE';
        const BAD_BALANCE: felt252 = 'BAD_BALANCE';
        const INVALID_TX: felt252 = 'INVALID_TX';
    }

    /// Calculates the rate of a given token by calculating value of 10 ** 18.
    /// Note that later when using this rate, the value will be divided by this value.
    /// Note the is_round is false here. This is because we want an accurate result
    /// and 10 ** 18 will not convert to zero.
    fn _get_rate(token_config: TokenConfig) -> u256 {
        _get_value_in_threshold_currency(token_config, Consts::ETHER, false)
    }

    /// Calculates value of amount with a given fee
    #[inline(always)]
    fn _get_value_in_threshold_currency_with_rate(fee_rate: u128, amount: u256) -> u128 {
        mulDiv(amount, fee_rate.into(), Consts::ETHER).try_into().unwrap() + 1
    }

    /// This function calculates the value of amount in the threshold currency using price
    /// from the external price service.
    /// Note: the USDC decimals are 6 while other tokens like eth have 18 decimals.
    /// This means that for low enough amounts of eth, this function will evaluate to zero.
    /// To prevent a scenario in which small enough amounts of eth are spent but always get
    /// evaluated to zero and so the daily spending does not increase, we add an option to
    /// add an extra + 1. The only scenario where we don't add this +1 is when
    /// we calculate rate in _get_rate since the input there is 10**18.
    fn _get_value_in_threshold_currency(
        token_config: TokenConfig, amount: u256, is_round: bool,
    ) -> u256 {
        let round = if is_round {
            1
        } else {
            0
        };
        let sqrt_price_x96_sqr = IPoolPriceDispatcher {
            contract_address: MainnetConfig::PRICE_CONTRACT_ADDRESS.try_into().unwrap(),
        }
            .get_average_price(token_config.pool_key, Consts::DAY_SEC);
        assert(sqrt_price_x96_sqr != 0_u256, Errors::INVALID_PRICE);
        // usdc is token0 => rate ** 2 == ([eth / usdc]) **2
        if token_config.is_threshold_currency_token0 {
            mulDiv(amount, Consts::X96, sqrt_price_x96_sqr) + round
        } else {
            mulDiv(amount, sqrt_price_x96_sqr, Consts::X96) + round
        }
    }


    #[embeddable_as(RateServiceInternalImpl)]
    impl InternalImpl<
        TContractState, +HasComponent<TContractState>,
    > of IRateServiceInternal<ComponentState<TContractState>> {
        /// Calculates fee based on the transaction version and the fee amount.
        fn _analyze_fee(
            self: @ComponentState<TContractState>, fee: u256, version: felt252,
        ) -> FeeInfoResponse {
            let fee_config = if version == 3 {
                self._get_stark_fee_token_config()
            } else {
                self._get_eth_fee_token_config()
            };
            let fee_rate = _get_rate(fee_config);
            return FeeInfoResponse {
                fee_rate: fee_rate,
                fee_in_threshold_currency: _get_value_in_threshold_currency_with_rate(
                    fee_rate.try_into().unwrap(), fee,
                )
                    .into(),
                is_stark_fee: (version == 3),
            };
        }

        /// This function empties out all the custom whitelisted token configuration
        /// from all relevant storage items.
        fn _clear_token_config(ref self: ComponentState<TContractState>) {
            let mut i = 0;
            let custom_token_len = self.white_listed_custom_list_length.read();
            loop {
                if i >= custom_token_len {
                    break;
                }

                let token_address = self.white_listed_custom_list.read(i);
                self
                    .white_listed_tokens_map
                    .write(
                        token_address,
                        TokenConfig {
                            token_address: 0.try_into().unwrap(),
                            pool_key: 0,
                            is_threshold_currency: false,
                            is_threshold_currency_token0: false,
                        },
                    );
                self.white_listed_custom_list.write(i, 0.try_into().unwrap());
                i += 1;
            }
            self.white_listed_custom_list_length.write(0);
        }

        /// Rewrites rate configuration
        /// @param white_listed_tokens - tokens which will be allowed to transfer out of the account
        /// as part of a dwl bypass call
        /// @param white_listed_calls_list - list of contract addresses and selectors which will be
        /// allowed as part of a dwl bypass call
        fn _update_config_inner(
            ref self: ComponentState<TContractState>,
            mut white_listed_tokens: Span<TokenConfig>,
            mut white_listed_calls_list: Span<WhitelistCallConfig>,
        ) {
            self._clear_token_config();

            let mut i: u8 = 0;
            loop {
                match white_listed_tokens.pop_front() {
                    Option::Some(token_config) => {
                        self
                            .white_listed_tokens_map
                            .write(*token_config.token_address, *token_config);
                        self.white_listed_custom_list.write(i, *token_config.token_address);
                        i += 1;
                    },
                    Option::None => { break; },
                };
            }
            self.white_listed_custom_list_length.write(i);

            loop {
                match white_listed_calls_list.pop_front() {
                    Option::Some(call_config) => {
                        let whitelist_type: WhitelistCallType = if *call_config
                            .whitelist_call_type == 1 {
                            WhitelistCallType::OneApprove
                        } else if *call_config.whitelist_call_type == 2 {
                            WhitelistCallType::TwoApproves
                        } else {
                            WhitelistCallType::Deleted
                        };
                        self
                            .white_listed_contracts_and_selectors
                            .write((*call_config.to, *call_config.selector), whitelist_type);
                    },
                    Option::None => { break; },
                };
            };
        }

        /// Fetches all required info on a token based on configuration or hard coded values
        /// if configuration is missing. If no configuration for token present the pool_key
        /// will be zero and the is_threshold_currency flag will be set to false indicating
        /// the caller that the configuration is missing
        fn _get_token_config(
            self: @ComponentState<TContractState>, to: ContractAddress,
        ) -> TokenConfig {
            let token_config: TokenConfig = self.white_listed_tokens_map.read(to);
            if token_config.pool_key == 0 && !token_config.is_threshold_currency {
                if to == MainnetConfig::ETH_ADDRESS.try_into().unwrap() {
                    return TokenConfig {
                        token_address: to,
                        pool_key: MainnetConfig::ETH_USDC_POOL_KEY,
                        is_threshold_currency: false,
                        is_threshold_currency_token0: false,
                    };
                } else if to == MainnetConfig::STARK_ADDRESS.try_into().unwrap() {
                    return TokenConfig {
                        token_address: to,
                        pool_key: MainnetConfig::STARK_USDC_POOL_KEY,
                        is_threshold_currency: false,
                        is_threshold_currency_token0: false,
                    };
                } else if to == MainnetConfig::USDT_ADDRESS.try_into().unwrap() {
                    return TokenConfig {
                        token_address: to,
                        pool_key: MainnetConfig::USDT_USDC_POOL_KEY,
                        is_threshold_currency: false,
                        is_threshold_currency_token0: true,
                    };
                } else if to == MainnetConfig::WBTC_ADDRESS.try_into().unwrap() {
                    return TokenConfig {
                        token_address: to,
                        pool_key: MainnetConfig::WBTC_USDC_POOL_KEY,
                        is_threshold_currency: false,
                        is_threshold_currency_token0: false,
                    };
                } else if to == MainnetConfig::USDC_ADDRESS.try_into().unwrap() {
                    return TokenConfig {
                        token_address: to,
                        pool_key: 0,
                        is_threshold_currency: true,
                        is_threshold_currency_token0: false,
                    };
                }
                return TokenConfig {
                    token_address: 0.try_into().unwrap(),
                    pool_key: 0,
                    is_threshold_currency: false,
                    is_threshold_currency_token0: false,
                };
            } else {
                return token_config;
            }
        }

        fn _get_whitelist_call_type(
            self: @ComponentState<TContractState>, to: ContractAddress, selector: felt252,
        ) -> WhitelistCallType {
            self.white_listed_contracts_and_selectors.read((to, selector))
        }

        /// Fetches token config of eth
        fn _get_eth_fee_token_config(self: @ComponentState<TContractState>) -> TokenConfig {
            let eth_token_config = self.fee_token.read();
            let zero: ContractAddress = 0.try_into().unwrap();
            if eth_token_config.token_address == zero {
                self._get_token_config(MainnetConfig::ETH_ADDRESS.try_into().unwrap())
            } else {
                eth_token_config
            }
        }

        /// Fetches token config of the stark token
        fn _get_stark_fee_token_config(self: @ComponentState<TContractState>) -> TokenConfig {
            let stark_token_config = self.stark_fee_token.read();
            let zero: ContractAddress = 0.try_into().unwrap();
            if stark_token_config.token_address == zero {
                self._get_token_config(MainnetConfig::STARK_ADDRESS.try_into().unwrap())
            } else {
                stark_token_config
            }
        }

        /// Fetches eth rate from price service
        fn _get_eth_fee_rate(self: @ComponentState<TContractState>) -> u128 {
            let eth_fee_config = self._get_eth_fee_token_config();
            return _get_rate(eth_fee_config).try_into().unwrap();
        }

        /// Fetches stark rate from price service
        fn _get_stark_fee_rate(self: @ComponentState<TContractState>) -> u128 {
            let stark_fee_config = self._get_stark_fee_token_config();
            return _get_rate(stark_fee_config).try_into().unwrap();
        }

        /// Fetches eth rate from storage
        fn _get_stored_eth_fee_rate(self: @ComponentState<TContractState>) -> u128 {
            self.stored_fee_rate_eth.read()
        }

        /// Fetches stark rate from storage
        fn _get_stored_stark_fee_rate(self: @ComponentState<TContractState>) -> u128 {
            self.stored_fee_rate_stark.read()
        }

        /// Sets eth rate in storage
        fn _set_stored_eth_fee_rate(ref self: ComponentState<TContractState>, rate: u128) {
            self.stored_fee_rate_eth.write(rate);
        }

        /// Sets stark rate in storage
        fn _set_stored_stark_fee_rate(ref self: ComponentState<TContractState>, rate: u128) {
            self.stored_fee_rate_stark.write(rate);
        }

        /// Calculates this transaction's fee value based on given rate
        fn _calc_fee_value_with_rate(
            self: @ComponentState<TContractState>, fee_rate: u128, fee: u256,
        ) -> u128 {
            _get_value_in_threshold_currency_with_rate(fee_rate, fee)
        }

        /// Calculates a given fee value based on stored rate
        fn _calc_fee_value_with_stored_rate_by_version(
            self: @ComponentState<TContractState>, fee: u256, version: felt252,
        ) -> u128 {
            if version == 3 {
                _get_value_in_threshold_currency_with_rate(
                    self.stored_fee_rate_stark.read().into(), fee,
                )
            } else if version == 1 || version == 0 {
                _get_value_in_threshold_currency_with_rate(
                    self.stored_fee_rate_eth.read().into(), fee,
                )
            } else {
                panic_with_felt252(Errors::INVALID_TX);
                0
            }
        }


        /// This function calls the standard erc-20 balanceof method
        fn _get_token_balance(
            self: @ComponentState<TContractState>, token_address: ContractAddress,
        ) -> u256 {
            IERC20BalanceOfDispatcher { contract_address: token_address }
                .balanceOf(get_contract_address())
        }

        /// This function fetches the balances of all relevant tokens including custom tokens
        /// the user had added manually and the hardcoded mainnet tokens. The function first
        /// iterates over the custom tokens based on white_listed_custom_list_length. After that
        /// it iterates over the hardcoded mainnet tokens and adds those as well. In the first
        /// iteration it tracks the custom tokens so that it could skip hardcoded tokens that
        /// were manually modified by the user. Theres also a way in which a user can block
        /// certain mainnet hardcoded tokens. It can set them with pool key 0 and false on
        /// is_threshold_currency.
        fn _get_balance_report(
            self: @ComponentState<TContractState>,
        ) -> Span<(ContractAddress, u256)> {
            let mut result: Array<(ContractAddress, u256)> = array![];

            let mut i = 0;
            let custom_token_len = self.white_listed_custom_list_length.read();
            let mut token_track_dict: Felt252Dict<bool> = Default::default();
            loop {
                if i >= custom_token_len {
                    break;
                }

                let token_address = self.white_listed_custom_list.read(i);
                // To support removing tokens which were previously hardcoded
                // a user can add one of the hardcoded tokens to the custom token list
                // and mark it without a pool key and not as a threshold currency
                let custom_token_config: TokenConfig = self
                    .white_listed_tokens_map
                    .read(token_address);
                if custom_token_config.pool_key != 0 || custom_token_config.is_threshold_currency {
                    let token_balance = self._get_token_balance(token_address);
                    result.append((token_address.try_into().unwrap(), token_balance));
                }
                token_track_dict.insert(token_address.into(), true);
                i += 1;
            }

            if token_track_dict.get(MainnetConfig::ETH_ADDRESS) == false {
                let eth_address: ContractAddress = MainnetConfig::ETH_ADDRESS.try_into().unwrap();
                let token_balance = self._get_token_balance(eth_address);
                result.append((eth_address, token_balance));
            }
            if token_track_dict.get(MainnetConfig::STARK_ADDRESS) == false {
                let stark_address: ContractAddress = MainnetConfig::STARK_ADDRESS
                    .try_into()
                    .unwrap();
                let token_balance = self._get_token_balance(stark_address);
                result.append((stark_address, token_balance));
            }
            if token_track_dict.get(MainnetConfig::USDT_ADDRESS) == false {
                let usdt_address: ContractAddress = MainnetConfig::USDT_ADDRESS.try_into().unwrap();
                let token_balance = self._get_token_balance(usdt_address);
                result.append((usdt_address, token_balance));
            }
            if token_track_dict.get(MainnetConfig::WBTC_ADDRESS.try_into().unwrap()) == false {
                let wbtc_address: ContractAddress = MainnetConfig::WBTC_ADDRESS.try_into().unwrap();
                let token_balance = self._get_token_balance(wbtc_address);
                result.append((wbtc_address, token_balance));
            }
            if token_track_dict.get(MainnetConfig::USDC_ADDRESS.try_into().unwrap()) == false {
                let usdc_address: ContractAddress = MainnetConfig::USDC_ADDRESS.try_into().unwrap();
                let token_balance = self._get_token_balance(usdc_address);
                result.append((usdc_address, token_balance));
            }

            return result.span();
        }

        /// This function returns the diff in the threshold currency between the old and new
        /// balance of a given token. If the new balance is higher then we return zero since
        /// we only care about decreases in value since value gained in transaction is not
        /// credited to the daily spending.
        fn _get_diff_in_threshold_currency(
            self: @ComponentState<TContractState>,
            old_balance: u256,
            new_balance: u256,
            token_address: ContractAddress,
        ) -> u256 {
            if new_balance < old_balance {
                let diff: u256 = old_balance - new_balance;
                let token_config = self._get_token_config(token_address);
                if token_config.is_threshold_currency {
                    return diff;
                } else {
                    let value_of_diff_in_threshold_currency = _get_value_in_threshold_currency(
                        token_config, diff, true,
                    );
                    return value_of_diff_in_threshold_currency;
                }
            }
            return 0;
        }

        /// This function sums up the diff of all tracked tokens between their current balance
        /// and what is given in the input and returns it in the threshold currency.
        fn _analyze_change_in_balance(
            self: @ComponentState<TContractState>, previous_report: Span<(ContractAddress, u256)>,
        ) -> u128 {
            let new_report: Span<(ContractAddress, u256)> = self._get_balance_report();
            assert(new_report.len() == previous_report.len(), Errors::BAD_BALANCE);

            let mut total_delta: u256 = 0;
            let mut i: u32 = 0;

            loop {
                if i >= new_report.len() {
                    break;
                }
                let (old_add, old_token_balance) = *previous_report.at(i);
                let (new_add, new_token_balance) = *new_report.at(i);
                assert(old_add == new_add, Errors::BAD_BALANCE);
                total_delta += self
                    ._get_diff_in_threshold_currency(old_token_balance, new_token_balance, old_add);
                i += 1;
            }

            return total_delta.try_into().unwrap();
        }
    }

    #[embeddable_as(RateConfigImpl)]
    impl ExternalImpl<
        TContractState, +HasComponent<TContractState>,
    > of IRateServiceExternal<ComponentState<TContractState>> {
        /// Updates rate configuration
        /// @param white_listed_tokens - tokens which will be allowed to transfer out of the account
        /// as part of a dwl bypass call
        /// @param white_listed_calls_list - list of contract addresses and selectors which will be
        /// allowed as part of a dwl bypass call
        fn update_rate_config(
            ref self: ComponentState<TContractState>,
            white_listed_tokens: Span<TokenConfig>,
            white_listed_calls_list: Span<WhitelistCallConfig>,
        ) {
            assert_self_caller();
            self._update_config_inner(white_listed_tokens, white_listed_calls_list);
        }
    }
}
