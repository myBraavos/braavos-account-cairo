#[starknet::component]
mod OutsideExecComponent {
    use braavos_account::outside_execution::interface::{IOutsideExecution_V2, OutsideExecution};
    use braavos_account::outside_execution::hash::calculate_outside_execution_hash;
    use braavos_account::account::interface::IBraavosAccountInternal;
    use braavos_account::utils::utils::execute_calls;
    use starknet::{
        ContractAddress, get_contract_address, get_caller_address, get_block_timestamp, get_tx_info
    };
    use starknet::account::Call;

    mod Errors {
        const SELF_CALL: felt252 = 'SELF_CALL';
        const INVALID_CALLER: felt252 = 'INVALID_CALLER';
        const INVALID_TIMESTAMP: felt252 = 'INVALID_TIMESTAMP';
        const INVALID_NONCE: felt252 = 'INVALID_NONCE';
        const INVALID_SIG: felt252 = 'INVALID_SIG';
    }

    #[storage]
    struct Storage {
        outside_nonces: LegacyMap<felt252, bool>
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {}

    #[embeddable_as(OutsideExecImpl)]
    impl ExternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        +IBraavosAccountInternal<TContractState>,
        +Drop<TContractState>,
    > of IOutsideExecution_V2<ComponentState<TContractState>> {
        fn execute_from_outside_v2(
            ref self: ComponentState<TContractState>,
            outside_execution: OutsideExecution,
            signature: Span<felt252>
        ) -> Array<Span<felt252>> {
            validate_caller(outside_execution.caller);
            validate_no_self_calls(outside_execution.calls);
            let timestamp = validate_timestamp(
                outside_execution.execute_after, outside_execution.execute_before
            );
            assert(
                self.is_valid_outside_execution_nonce(outside_execution.nonce),
                Errors::INVALID_NONCE
            );

            let tx_hash = calculate_outside_execution_hash(@outside_execution);
            let tx_ver = get_tx_info().unbox().version;

            assert(
                self
                    .get_contract()
                    ._is_valid_signature_common(
                        tx_hash, signature, timestamp, tx_ver
                    ) == starknet::VALIDATED,
                Errors::INVALID_SIG
            );

            self.outside_nonces.write(outside_execution.nonce, true);

            execute_calls(outside_execution.calls)
        }

        fn is_valid_outside_execution_nonce(
            self: @ComponentState<TContractState>, nonce: felt252
        ) -> bool {
            !self.outside_nonces.read(nonce)
        }
    }

    fn validate_caller(caller: ContractAddress) {
        if caller.into() != 'ANY_CALLER' {
            assert(get_caller_address() == caller, Errors::INVALID_CALLER);
        }
    }

    fn validate_no_self_calls(mut calls: Span<Call>) {
        let self_address = get_contract_address();
        loop {
            match calls.pop_front() {
                Option::Some(call) => { assert(*call.to != self_address, Errors::SELF_CALL); },
                Option::None(_) => { break; },
            };
        };
    }

    fn validate_timestamp(execute_after: u64, execute_before: u64) -> u64 {
        let timestamp = get_block_timestamp();
        assert(execute_after < timestamp && timestamp < execute_before, Errors::INVALID_TIMESTAMP);
        timestamp
    }
}
