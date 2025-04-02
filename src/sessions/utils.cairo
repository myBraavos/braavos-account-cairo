use braavos_account::sessions::hash::hash_allowed_method;
use braavos_account::sessions::interface::{
    CalldataValidation, CalldataValidationSpan, CalldataValidationType,
    GasSponsoredSessionExecutionRequest, GasSponsoredSessionExecutionRequestV2,
    SessionExecuteRequest, SessionExecuteRequestV2, SessionExecuteV2, SessionKeyVersion,
};
use starknet::account::Call;
use starknet::get_contract_address;

mod Errors {
    const BAD_CALL_HINT: felt252 = 'BAD_CALL_HINT';
    const BAD_CALL: felt252 = 'BAD_CALL';
    const BAD_CALLDATA: felt252 = 'BAD_CALLDATA';
}

mod Consts {
    const SESSION_EXECUTE_SELECTOR: felt252 = selector!("session_execute");
    const SESSION_EXECUTE_SELECTOR_V2: felt252 = selector!("session_execute_v2");
    const SESSION_REVOKE_SELECTOR: felt252 = selector!("revoke_session");
    const TRANSFER_CALL_SELECTOR: felt252 = selector!("transfer");
    const APPROVE_CALL_SELECTOR: felt252 = selector!("approve");
    const INCREASE_ALLOWANCE_CALL_SELECTOR: felt252 = selector!("increase_allowance");
    const INCREASE_ALLOWANCE_CAMEL_CALL_SELECTOR: felt252 = selector!("increaseAllowance");
    const TRANSFER_FROM_CALL_SELECTOR: felt252 = selector!("transfer_from");
    const TRANSFER_FROM_CAMEL_CALL_SELECTOR: felt252 = selector!("transferFrom");
    const DAI_MAINNET_V0_ADDRESS: felt252 =
        0x00da114221cb83fa859dbdb4c44beeaa0bb37c7537ad5ae66fe5e0efd20e6eb3;
    const DAI_MAINNET_V2_ADDRESS: felt252 =
        0x05574eb6b8789a91466f902c380d978e472db68170ff82a5b650b95a58ddf4ad;
}

fn validate_calldata_conditions(calldata: Span<felt252>, validations: Span<CalldataValidation>) {
    for validation in validations {
        assert(*validation.validation_type == CalldataValidationType::Eq, Errors::BAD_CALLDATA);
        assert(calldata.len() > *validation.offset, Errors::BAD_CALLDATA);
        assert(*calldata.at(*validation.offset) == *validation.value, Errors::BAD_CALLDATA);
    }
}

fn validate_allowed_methods(
    allowed_method_guids: Span<felt252>,
    allowed_method_calldata_validations: Span<CalldataValidationSpan>,
    calls: Span<Call>,
    calls_hint: Span<u32>,
    session_key_version: SessionKeyVersion,
) {
    assert(
        calls.len() == calls_hint.len()
            && (session_key_version == SessionKeyVersion::V1
                || allowed_method_guids.len() == allowed_method_calldata_validations.len()),
        Errors::BAD_CALL_HINT,
    );

    let mut index = 0;
    loop {
        if (index >= calls.len()) {
            break;
        }
        let call = calls.at(index);
        let call_index = *calls_hint.at(index);
        assert(call_index < allowed_method_guids.len(), Errors::BAD_CALL_HINT);

        if session_key_version == SessionKeyVersion::V2 {
            validate_calldata_conditions(
                *call.calldata, *allowed_method_calldata_validations.at(call_index),
            );
        }
        assert(
            hash_allowed_method(
                *call.to,
                *call.selector,
                if session_key_version == SessionKeyVersion::V1 {
                    array![].span()
                } else {
                    *allowed_method_calldata_validations.at(call_index)
                },
                session_key_version,
            ) == *allowed_method_guids
                .at(call_index),
            Errors::BAD_CALL,
        );
        index += 1;
    };
}

fn is_session_execute(calls: Span<Call>) -> bool {
    calls.len() > 1
        && *calls.at(0).to == get_contract_address()
        && (*calls.at(0).selector == Consts::SESSION_EXECUTE_SELECTOR
            || *calls.at(0).selector == Consts::SESSION_EXECUTE_SELECTOR_V2)
}

fn get_session_execute_version(calls: Span<Call>) -> SessionKeyVersion {
    if *calls.at(0).selector == Consts::SESSION_EXECUTE_SELECTOR {
        SessionKeyVersion::V1
    } else {
        SessionKeyVersion::V2
    }
}

fn is_erc20_token_removal_call(call: @Call) -> bool {
    (*call.selector == Consts::TRANSFER_CALL_SELECTOR
        || *call.selector == Consts::APPROVE_CALL_SELECTOR
        || *call.selector == Consts::INCREASE_ALLOWANCE_CALL_SELECTOR
        || *call.selector == Consts::INCREASE_ALLOWANCE_CAMEL_CALL_SELECTOR)
        && (*call.calldata).len() == 3
}

fn is_dai_transfer_from_itself_call(call: @Call) -> bool {
    let calldata = *call.calldata;
    ((*call.to).into() == Consts::DAI_MAINNET_V0_ADDRESS
        || (*call.to).into() == Consts::DAI_MAINNET_V2_ADDRESS)
        && (*(calldata.at(0)) == get_contract_address().into())
        && (*call.selector == Consts::TRANSFER_FROM_CALL_SELECTOR
            || *call.selector == Consts::TRANSFER_FROM_CAMEL_CALL_SELECTOR)
        && (*call.calldata).len() == 4
}

impl SessionExecuteRequestIntoV2 of Into<SessionExecuteRequest, SessionExecuteRequestV2> {
    fn into(self: SessionExecuteRequest) -> SessionExecuteRequestV2 {
        SessionExecuteRequestV2 {
            session_request: SessionExecuteV2 {
                owner_pub_key: self.session_request.owner_pub_key,
                execute_after: self.session_request.execute_after,
                execute_before: self.session_request.execute_before,
                allowed_method_guids: self.session_request.allowed_method_guids,
                v3_gas_limit: self.session_request.v3_gas_limit,
                spending_limits: self.session_request.spending_limits,
                allowed_method_calldata_validations: array![].span(),
            },
            call_hints: self.call_hints,
            session_request_signature: self.session_request_signature,
        }
    }
}

impl GasSponsoredSessionExecutionRequestIntoV2 of Into<
    GasSponsoredSessionExecutionRequest, GasSponsoredSessionExecutionRequestV2,
> {
    fn into(self: GasSponsoredSessionExecutionRequest) -> GasSponsoredSessionExecutionRequestV2 {
        GasSponsoredSessionExecutionRequestV2 {
            execute_after: self.execute_after,
            execute_before: self.execute_before,
            allowed_method_guids: self.allowed_method_guids,
            allowed_method_calldata_validations: array![].span(),
            spending_limits: self.spending_limits,
            calls: self.calls,
            call_hints: self.call_hints,
        }
    }
}
