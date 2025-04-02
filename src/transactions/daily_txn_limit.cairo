/// # DailyTxnLimit Component
///
/// The DailyTxnLimit Component implements the functionality of limiting
/// the number of transactions per day for each signer of the contract

#[starknet::component]
mod DailyTxnLimit {
    use braavos_account::transactions::interface::{
        DailyTxnLimitExternalTrait, DailyTxnLimitInternalTrait,
    };
    use starknet::get_block_timestamp;
    use starknet::storage::Map;

    mod Consts {
        const ACCOUNT_DAILY_TXN_LIMIT: usize = 24;
    }

    mod Errors {
        const EXCEEDED_DAILY_LIMIT: felt252 = 'EXCEEDED_DAILY_LIMIT';
    }

    #[storage]
    struct Storage {
        _signer_daily_txn_count: Map<(felt252, u64), usize>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {}

    #[embeddable_as(DailyTxnLimitInternalImpl)]
    impl DailyTxnLimitInternal<
        TContractState, +HasComponent<TContractState>,
    > of DailyTxnLimitInternalTrait<ComponentState<TContractState>> {
        /// @param signer_guid Identifier of the signer for whom the number
        /// of daily transactions is checked and updated
        /// Checks that the signer has not exceeded the daily limit and
        /// writes the updated count of transactions
        ///
        /// Panic if the current number of transactions is equal to
        /// or greater than the daily limit
        fn _assert_and_update_daily_txn_limit(
            ref self: ComponentState<TContractState>, signer_guid: felt252,
        ) {
            let days_since_epoch = get_block_timestamp() / 86400_u64;
            let curr = self._signer_daily_txn_count.read((signer_guid, days_since_epoch));
            assert(curr < Consts::ACCOUNT_DAILY_TXN_LIMIT, Errors::EXCEEDED_DAILY_LIMIT);

            self._signer_daily_txn_count.write((signer_guid, days_since_epoch), curr + 1_usize);
        }
    }

    #[embeddable_as(DailyTxnLimitExternalImpl)]
    impl DailyTxnLimitExternal<
        TContractState, +HasComponent<TContractState>,
    > of DailyTxnLimitExternalTrait<ComponentState<TContractState>> {
        /// @param signer_guid Identifier of the signer for whom the
        /// number of daily transactions is checked
        /// @param days_since_epoch The day for which the number of transactions
        /// is requested.
        /// @return count of transactions performed by signer with signer_id
        /// on the specified day
        fn get_tx_count(
            self: @ComponentState<TContractState>, signer_guid: felt252, days_since_epoch: u64,
        ) -> usize {
            self._signer_daily_txn_count.read((signer_guid, days_since_epoch))
        }
    }
}
