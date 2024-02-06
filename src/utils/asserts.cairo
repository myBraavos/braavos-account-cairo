use starknet::{get_contract_address, get_caller_address};

fn assert_self_caller() {
    assert(get_contract_address() == get_caller_address(), 'INVALID_CALLER');
}
