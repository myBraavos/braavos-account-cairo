use braavos_account::utils::snip12::{calculate_snip12_hash, hash_call};
use braavos_account::sessions::interface::{
    CalldataValidation, GasSponsoredSessionExecutionRequest, GasSponsoredSessionExecutionRequestV2,
    SessionExecute, SessionExecuteV2, SessionKeyVersion, TokenAmount,
};
use poseidon::poseidon_hash_span;
use starknet::ContractAddress;

const U256_TYPE_HASH: felt252 = selector!("\"u256\"(\"low\":\"u128\",\"high\":\"u128\")");

const CALLDATA_VALIDATION_TYPE_HASH: felt252 =
    selector!(
        "\"CalldataValidation\"(\"Offset\":\"u128\",\"Value\":\"felt\",\"Validation Type\":\"u128\")",
    );

const ALLOWED_METHOD_TYPE_HASH: felt252 =
    selector!(
        "\"AllowedMethod\"(\"Contract Address\":\"ContractAddress\",\"Selector\":\"selector\")"
    );

const ALLOWED_METHOD_TYPE_HASH_V2: felt252 =
    selector!(
        "\"AllowedMethod\"(\"Contract Address\":\"ContractAddress\",\"Selector\":\"selector\",\"Calldata Validations\":\"CalldataValidation*\")\"CalldataValidation\"(\"Offset\":\"u128\",\"Value\":\"felt\",\"Validation Type\":\"u128\")",
    );

const TOKEN_AMOUNT_TYPE_HASH: felt252 =
    selector!(
        "\"TokenAmount\"(\"token_address\":\"ContractAddress\",\"amount\":\"u256\")\"u256\"(\"low\":\"u128\",\"high\":\"u128\")"
    );

const GAS_SPONSORED_SESSION_EXECUTION_TYPE_HASH: felt252 =
    selector!(
        "\"GasSponsoredSessionExecution\"(\"Caller\":\"ContractAddress\",\"Execute After\":\"timestamp\",\"Execute Before\":\"timestamp\",\"Allowed Methods\":\"AllowedMethod*\",\"Spending Limits\":\"TokenAmount*\")\"AllowedMethod\"(\"Contract Address\":\"ContractAddress\",\"Selector\":\"selector\")\"TokenAmount\"(\"token_address\":\"ContractAddress\",\"amount\":\"u256\")\"u256\"(\"low\":\"u128\",\"high\":\"u128\")"
    );

const GAS_SPONSORED_SESSION_EXECUTION_TYPE_HASH_V2: felt252 =
    selector!(
        "\"GasSponsoredSessionExecution\"(\"Caller\":\"ContractAddress\",\"Execute After\":\"timestamp\",\"Execute Before\":\"timestamp\",\"Allowed Methods\":\"AllowedMethod*\",\"Spending Limits\":\"TokenAmount*\")\"AllowedMethod\"(\"Contract Address\":\"ContractAddress\",\"Selector\":\"selector\",\"Calldata Validations\":\"CalldataValidation*\")\"CalldataValidation\"(\"Offset\":\"u128\",\"Value\":\"felt\",\"Validation Type\":\"u128\")\"TokenAmount\"(\"token_address\":\"ContractAddress\",\"amount\":\"u256\")\"u256\"(\"low\":\"u128\",\"high\":\"u128\")",
    );

const SESSION_EXECUTION_TYPE_HASH: felt252 =
    selector!(
        "\"SessionExecution\"(\"Owner Public Key\":\"felt\",\"Execute After\":\"timestamp\",\"Execute Before\":\"timestamp\",\"STRK Gas Limit\":\"u128\",\"Allowed Methods\":\"AllowedMethod*\",\"Spending Limits\":\"TokenAmount*\")\"AllowedMethod\"(\"Contract Address\":\"ContractAddress\",\"Selector\":\"selector\")\"TokenAmount\"(\"token_address\":\"ContractAddress\",\"amount\":\"u256\")\"u256\"(\"low\":\"u128\",\"high\":\"u128\")"
    );

const SESSION_EXECUTION_TYPE_HASH_V2: felt252 =
    selector!(
        "\"SessionExecution\"(\"Owner Public Key\":\"felt\",\"Execute After\":\"timestamp\",\"Execute Before\":\"timestamp\",\"STRK Gas Limit\":\"u128\",\"Allowed Methods\":\"AllowedMethod*\",\"Spending Limits\":\"TokenAmount*\")\"AllowedMethod\"(\"Contract Address\":\"ContractAddress\",\"Selector\":\"selector\",\"Calldata Validations\":\"CalldataValidation*\")\"CalldataValidation\"(\"Offset\":\"u128\",\"Value\":\"felt\",\"Validation Type\":\"u128\")\"TokenAmount\"(\"token_address\":\"ContractAddress\",\"amount\":\"u256\")\"u256\"(\"low\":\"u128\",\"high\":\"u128\")",
    );

fn get_gas_sponsored_session_execution_type_hash(
    session_key_version: SessionKeyVersion,
) -> felt252 {
    if session_key_version == SessionKeyVersion::V1 {
        GAS_SPONSORED_SESSION_EXECUTION_TYPE_HASH
    } else {
        GAS_SPONSORED_SESSION_EXECUTION_TYPE_HASH_V2
    }
}

fn get_session_execution_type_hash(session_key_version: SessionKeyVersion) -> felt252 {
    if session_key_version == SessionKeyVersion::V1 {
        SESSION_EXECUTION_TYPE_HASH
    } else {
        SESSION_EXECUTION_TYPE_HASH_V2
    }
}

fn get_allowed_method_type_hash(session_key_version: SessionKeyVersion) -> felt252 {
    if session_key_version == SessionKeyVersion::V1 {
        ALLOWED_METHOD_TYPE_HASH
    } else {
        ALLOWED_METHOD_TYPE_HASH_V2
    }
}

fn calculate_gas_sponsored_session_execution_hash(
    gas_sponsored_execution: @GasSponsoredSessionExecutionRequestV2,
    caller: ContractAddress,
    session_key_version: SessionKeyVersion,
) -> felt252 {
    calculate_snip12_hash(
        'Account.execute_gs_session',
        if session_key_version == SessionKeyVersion::V2 {
            3
        } else {
            2
        },
        hash_gas_sponsored_session_execution(gas_sponsored_execution, caller, session_key_version),
    )
}

fn hash_gas_sponsored_session_execution(
    execution: @GasSponsoredSessionExecutionRequestV2,
    caller: ContractAddress,
    session_key_version: SessionKeyVersion,
) -> felt252 {
    poseidon_hash_span(
        array![
            get_gas_sponsored_session_execution_type_hash(session_key_version),
            (caller).into(),
            (*execution.execute_after).into(),
            (*execution.execute_before).into(),
            hash_allowed_methods_guids(*execution.allowed_method_guids),
            hash_spending_limits(*execution.spending_limits),
        ]
            .span()
    )
}


fn calculate_session_execute_hash(
    session_execute_request: @SessionExecuteV2, session_key_version: SessionKeyVersion,
) -> felt252 {
    calculate_snip12_hash(
        'Account.execute_session',
        if session_key_version == SessionKeyVersion::V2 {
            3
        } else {
            2
        },
        hash_session_execute(session_execute_request, session_key_version),
    )
}

fn hash_session_execute(
    request: @SessionExecuteV2, session_key_version: SessionKeyVersion,
) -> felt252 {
    poseidon_hash_span(
        array![
            get_session_execution_type_hash(session_key_version),
            *request.owner_pub_key,
            (*request.execute_after).into(),
            (*request.execute_before).into(),
            (*request.v3_gas_limit).into(),
            hash_allowed_methods_guids(*request.allowed_method_guids),
            hash_spending_limits(*request.spending_limits),
        ]
            .span()
    )
}

fn hash_allowed_methods_guids(mut allowed_methods_guids: Span<felt252>) -> felt252 {
    poseidon_hash_span(allowed_methods_guids)
}

fn hash_spending_limits(mut spending_limits: Span<TokenAmount>) -> felt252 {
    let mut hashed_token_amounts: Array<felt252> = array![];

    loop {
        match spending_limits.pop_front() {
            Option::Some(spending_limit) => {
                hashed_token_amounts.append(hash_token_amount(spending_limit));
            },
            Option::None(_) => { break; },
        };
    };
    poseidon_hash_span(hashed_token_amounts.span())
}

#[inline(always)]
fn hash_token_amount(token_amount: @TokenAmount) -> felt252 {
    poseidon_hash_span(
        array![
            TOKEN_AMOUNT_TYPE_HASH,
            (*token_amount.token_address).into(),
            hash_u256(*token_amount.amount)
        ]
            .span()
    )
}

fn hash_calldata_validation(calldata_validation: @CalldataValidation) -> felt252 {
    poseidon_hash_span(
        array![
            CALLDATA_VALIDATION_TYPE_HASH,
            (*calldata_validation.offset).into(),
            (*calldata_validation.value).into(),
            (*calldata_validation.validation_type).into(),
        ]
            .span(),
    )
}

fn hash_calldata_validations(mut calldata_validations: Span<CalldataValidation>) -> felt252 {
    let mut hashed_calldata_validations: Array<felt252> = array![];
    loop {
        match calldata_validations.pop_front() {
            Option::Some(calldata_validation) => {
                hashed_calldata_validations.append(hash_calldata_validation(calldata_validation));
            },
            Option::None(_) => { break; },
        };
    };
    poseidon_hash_span(hashed_calldata_validations.span())
}

fn hash_allowed_method(
    contract_address: ContractAddress,
    selector: felt252,
    calldata_validations: Span<CalldataValidation>,
    session_key_version: SessionKeyVersion,
) -> felt252 {
    let mut data: Array<felt252> = array![];
    data.append(get_allowed_method_type_hash(session_key_version));
    data.append(contract_address.into());
    data.append(selector);
    if session_key_version == SessionKeyVersion::V2 {
        data.append(hash_calldata_validations(calldata_validations));
    }
    poseidon_hash_span(data.span())
}

#[inline(always)]
fn hash_u256(amount: u256) -> felt252 {
    poseidon_hash_span(array![U256_TYPE_HASH, amount.low.into(), amount.high.into()].span())
}

