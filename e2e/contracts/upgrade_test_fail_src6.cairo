use core::serde::Serde;
use array::{ArrayTrait, SpanTrait};
use debug::PrintTrait;
use starknet::account::Call;
use starknet::ClassHash;


#[starknet::interface]
trait IUpgradeTarget<T> {
    fn supports_interface(self: @T, interface_id: felt252) -> bool;
    fn migrate_storage(ref self: T, from_version: felt252);
}

#[starknet::contract]
mod UpgradeTarget {
    use super::{ArrayTrait, Call, ClassHash, SpanTrait, IUpgradeTarget};
    use box::BoxTrait;
    use option::OptionTrait;
    use starknet::{get_tx_info, SyscallResultTrait, TxInfo};
    use starknet::syscalls::{library_call_syscall, replace_class_syscall};
    use traits::{Into, TryInto};

    const SRC6_ID: felt252 = 0x2ceccef7f994940b3962a6c67e0ba4fcd37df7d131417c604f91e03caecc1cd;

    #[storage]
    struct Storage {
        storage_migration_ver: felt252,
    }


    #[external(v0)]
    impl ExternalMethods of IUpgradeTarget<ContractState> {
        fn supports_interface(self: @ContractState, interface_id: felt252) -> bool {
            false
        }

        fn migrate_storage(ref self: ContractState, from_version: felt252) {
            panic_with_felt252('NOT_SUPPORTED_IN_THIS_TEST');
        }
    }
}

