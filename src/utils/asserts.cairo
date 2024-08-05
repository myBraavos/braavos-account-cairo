use starknet::{get_contract_address, get_caller_address, get_block_timestamp};
use starknet::account::Call;

fn assert_self_caller() {
    assert(get_contract_address() == get_caller_address(), 'INVALID_CALLER');
}

fn assert_no_self_calls(mut calls: Span<Call>) {
    let self_address = get_contract_address();
    loop {
        match calls.pop_front() {
            Option::Some(call) => { assert(*call.to != self_address, 'SELF_CALL'); },
            Option::None(_) => { break; },
        };
    };
}

fn assert_timestamp(execute_after: u64, execute_before: u64) -> u64 {
    let timestamp = get_block_timestamp();
    assert_timestamp_2(execute_after, execute_before, timestamp);
    timestamp
}


fn assert_timestamp_2(execute_after: u64, execute_before: u64, timestamp: u64) {
    assert(execute_after < timestamp && timestamp < execute_before, 'INVALID_TIMESTAMP');
}
