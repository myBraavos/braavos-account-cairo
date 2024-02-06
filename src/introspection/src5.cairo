#[starknet::component]
mod SRC5Component {
    use braavos_account::account::interface::{
        ISRC6_ID, IACCOUNT_ID_LEGACY_OZ_1, IACCOUNT_ID_LEGACY_OZ_2
    };
    use braavos_account::introspection::interface::{
        ISRC5WithCamelCase, ISRC5_ID, IERC165_ID_OZ_LEGACY
    };
    use braavos_account::outside_execution::interface::SRC5_OUTSIDE_EXECUTION_V2_INTERFACE_ID;

    #[storage]
    struct Storage {}

    #[embeddable_as(SRC5Impl)]
    impl ExternalImpl<
        TContractState, +HasComponent<TContractState>
    > of ISRC5WithCamelCase<ComponentState<TContractState>> {
        // Deprecated: used for backwards compatibility with Cairo 0 convention - remove after regenesis
        fn supportsInterface(self: @ComponentState<TContractState>, interfaceId: felt252) -> bool {
            self.supports_interface(interfaceId)
        }

        fn supports_interface(
            self: @ComponentState<TContractState>, interface_id: felt252
        ) -> bool {
            if interface_id == ISRC5_ID || interface_id == IERC165_ID_OZ_LEGACY {
                true
            } else if interface_id == ISRC6_ID
                || interface_id == IACCOUNT_ID_LEGACY_OZ_1
                || interface_id == IACCOUNT_ID_LEGACY_OZ_2 {
                true
            } else if interface_id == SRC5_OUTSIDE_EXECUTION_V2_INTERFACE_ID {
                true
            } else {
                false
            }
        }
    }
}

