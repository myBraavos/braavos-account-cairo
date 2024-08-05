use starknet::account::Call;
use starknet::ContractAddress;

#[derive(Copy, Drop, PartialEq, Serde)]
enum BypassCallType {
    #[default]
    NoDwl,
    NotBypassCall,
    ValidBypassCall,
}

#[derive(Copy, Drop, PartialEq, Serde)]
enum BypassRange {
    #[default]
    NA,
    LowerRange,
    MidRange,
    HighRange,
}

#[derive(Copy, Drop, PartialEq, Serde, starknet::Store)]
enum WhitelistCallType {
    #[default]
    NA,
    Deleted,
    OneApprove,
    TwoApproves,
}


mod MainnetConfig {
    const PRICE_CONTRACT_ADDRESS: felt252 =
        0x01d734056a9930cad68b2c4010d70a633486b3f04bdbd91b806555655b954642;
    const MYSWAP_CL_ADDRESS: felt252 =
        0x01114c7103e12c2b2ecbd3a2472ba9c48ddcbf702b1c242dd570057e26212111;

    const ETH_ADDRESS: felt252 = 0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7;
    const ETH_USDC_POOL_KEY: felt252 =
        0x71273c5c5780b4be42d9e6567b1b1a6934f43ab8abaf975c0c3da219fc4d040;

    const USDT_ADDRESS: felt252 =
        0x068f5c6a61780768455de69077e07e89787839bf8166decfbf92b645209c0fb8;
    const USDT_USDC_POOL_KEY: felt252 =
        0x7c5b7061e9e2e233b6ba9e084c3574c6575495721b18344c251d0234e1a77a3;

    const WBTC_ADDRESS: felt252 =
        0x03fe2b97c1fd336e750087d68b9b867997fd64a2661ff3ca5a7c771641e8e7ac;
    const WBTC_USDC_POOL_KEY: felt252 =
        0x27ee186f747e25bbbee5875754b8228730cc8f23ddf9492e63900a2b77d8a21;

    const STARK_ADDRESS: felt252 =
        0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d;
    const STARK_USDC_POOL_KEY: felt252 =
        0x69e3c70822347a8c2013c9b0af125f80b1f7cbf5ab05a6664dae7483226e375;

    const USDC_ADDRESS: felt252 =
        0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8;
}


/// PreExecuteBypassState Data structure that holds the state of user's balances right before the
/// execute @param - balance_report is a list of tokens and their balances
/// @param - bypass_call_type indicates whether this is a bypass call or not
/// @param - range_on_validate is the range that was deduced during the validate stage
#[derive(Copy, Drop, Serde)]
struct PreExecuteBypassState {
    balances: Span<(ContractAddress, u256)>,
    bypass_call_type: BypassCallType,
    range_on_validate: BypassRange,
}

#[starknet::interface]
trait IDwlExternal<TState> {
    // Daily withdrawal limit
    fn set_withdrawal_limit_low(ref self: TState, withdrawal_limit_low: u128);
    fn set_withdrawal_limit_high(ref self: TState, withdrawal_limit_high: u128);
    fn get_withdrawal_limit_low(self: @TState) -> u128;
    fn get_withdrawal_limit_high(self: @TState) -> u128;
    fn get_daily_spend(self: @TState) -> u128;
    fn get_fee_token_rate(self: @TState) -> u128;
    fn get_stark_fee_token_rate(self: @TState) -> u128;
}

#[starknet::interface]
trait IDwlInternal<TState> {
    fn _set_withdrawal_limit_high_inner(
        ref self: TState,
        withdrawal_limit_high: u128,
        fee_rate: u128,
        stark_fee_rate: u128,
        any_strong_signer: bool,
        is_multisig: bool
    );
    fn _set_withdrawal_limit_low_inner(
        ref self: TState,
        withdrawal_limit_low: u128,
        fee_rate: u128,
        stark_fee_rate: u128,
        any_strong_signer: bool
    );
    fn _get_withdrawal_limit_low_inner(self: @TState) -> u128;
    fn _get_withdrawal_limit_high_inner(self: @TState) -> u128;
    fn _update_fee_rate_and_adjust_daily_spending(
        ref self: TState,
        daily_spend: u128,
        fee: u256,
        fee_rate: u128,
        is_stark_fee: bool,
        existing_fee_rate: u128,
    ) -> u128;
    fn _ensure_fee_rate_exists(ref self: TState, fee_rate: u128, stark_fee_rate: u128);
    fn _handle_bypass_calls_on_validate(
        ref self: TState, block_timestamp: u64, calls: Span<Call>, fee: u256, version: felt252,
    ) -> BypassRange;
    fn _handle_bypass_calls_pre_execute(
        ref self: TState, calls: Span<Call>, block_timestamp: u64,
    ) -> PreExecuteBypassState;
    fn _calc_and_update_daily_spending_post_execute(
        ref self: TState,
        pre_execute_bypass_state: PreExecuteBypassState,
        block_timestamp: u64,
        fee: u256,
        version: felt252,
    ) -> (BypassRange, u128, u128, u128);
    fn _handle_bypass_calls_post_execute(
        ref self: TState,
        pre_execute_bypass_state: PreExecuteBypassState,
        block_timestamp: u64,
        stark_signer_validated: bool,
        strong_signer_validated: bool,
        signer_num: u8,
        multisig_threshold: u32,
        fee: u256,
        version: felt252,
    ) -> BypassCallType;

    fn _validate_call_structure(self: @TState, calls: Span<Call>) -> bool;
    fn _validate_triplet_call_structure(self: @TState, calls: Span<Call>) -> bool;
    fn _validate_couplet_call_structure(self: @TState, calls: Span<Call>) -> bool;
    fn _validate_single_call_structure(
        self: @TState,
        selector: felt252,
        to: ContractAddress,
        calldata: Span<felt252>,
        allowed_selector: felt252
    ) -> bool;
}

/// TokenConfig represents all info required to analyze the value of a transfer of a certain
/// token
/// @param - is_threshold_currency is true if this token is the token in which dwl limits
/// values are denominated.
/// @param - token_address
/// @param - pool_key is used to access myswap cl info on this token
/// @param - is_threshold_currency_token0 is true if address of threhold currency < token address
#[derive(Copy, Drop, Serde, starknet::Store)]
struct TokenConfig {
    is_threshold_currency: bool,
    token_address: ContractAddress,
    pool_key: felt252,
    is_threshold_currency_token0: bool,
}

/// WhitelistCallConfig represents a whitelisted call
/// @param - to is whitelisted contract address
/// @param - selector is whitelisted function selector
/// @param - whitelist_call_type: 1 means there should be 1 approval before, 2 allows 2 approvals
/// before
#[derive(Copy, Drop, Serde, starknet::Store)]
struct WhitelistCallConfig {
    to: ContractAddress,
    selector: felt252,
    whitelist_call_type: u8,
}

/// TransferInfoResponse represents the result of transaction value analysis
/// @param - value_in_threshold_currency - value of all transfers and approvals in transaction
/// @param - fee_in_threshold_currency - value of transaction fee
/// @param - is_all_whitelisted - are all calls whitelisted according to configuration
/// @param - fee_rate - current rate of used fee token
/// @param - is_stark_fee - is this a v3 transaction
#[derive(Copy, Drop, Serde)]
struct TransferInfoResponse {
    value_in_threshold_currency: u256,
    fee_in_threshold_currency: u256,
    is_all_whitelisted: bool,
    fee_rate: u256,
    is_stark_fee: bool,
}


/// FeeInfoResponse represents the result of transaction value analysis
/// @param - fee_in_threshold_currency - value of transaction fee
/// @param - fee_rate - current rate of used fee token
/// @param - is_stark_fee - is this a v3 transaction
#[derive(Copy, Drop, Serde)]
struct FeeInfoResponse {
    fee_in_threshold_currency: u256,
    fee_rate: u256,
    is_stark_fee: bool,
}


#[starknet::interface]
trait IRateServiceInternal<TState> {
    fn _analyze_fee(self: @TState, fee: u256, version: felt252) -> FeeInfoResponse;
    fn _get_token_config(self: @TState, to: ContractAddress) -> TokenConfig;
    fn _get_whitelist_call_type(
        self: @TState, to: ContractAddress, selector: felt252
    ) -> WhitelistCallType;
    fn _get_eth_fee_token_config(self: @TState) -> TokenConfig;
    fn _get_stark_fee_token_config(self: @TState) -> TokenConfig;
    fn _clear_token_config(ref self: TState);
    fn _update_config_inner(
        ref self: TState,
        white_listed_tokens: Span<TokenConfig>,
        white_listed_calls_list: Span<WhitelistCallConfig>,
    );
    fn _get_eth_fee_rate(self: @TState) -> u128;
    fn _get_stark_fee_rate(self: @TState) -> u128;
    fn _get_stored_eth_fee_rate(self: @TState) -> u128;
    fn _get_stored_stark_fee_rate(self: @TState) -> u128;
    fn _set_stored_eth_fee_rate(ref self: TState, rate: u128);
    fn _set_stored_stark_fee_rate(ref self: TState, rate: u128);
    // fn _calc_fee_value_with_stored_rate(self: @TState) -> u128;
    fn _calc_fee_value_with_stored_rate_by_version(
        self: @TState, fee: u256, version: felt252
    ) -> u128;
    fn _calc_fee_value_with_rate(self: @TState, fee_rate: u128, fee: u256) -> u128;

    fn _get_token_balance(self: @TState, token_address: ContractAddress) -> u256;
    fn _get_balance_report(self: @TState) -> Span<(ContractAddress, u256)>;
    fn _get_diff_in_threshold_currency(
        self: @TState, old_balance: u256, new_balance: u256, token_address: ContractAddress
    ) -> u256;
    fn _analyze_change_in_balance(
        self: @TState, previous_report: Span<(ContractAddress, u256)>
    ) -> u128;
}

#[starknet::interface]
trait IRateServiceExternal<TState> {
    fn update_rate_config(
        ref self: TState,
        white_listed_tokens: Span<TokenConfig>,
        white_listed_calls_list: Span<WhitelistCallConfig>,
    );
}

