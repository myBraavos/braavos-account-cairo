use core::serde::Serde;
use debug::PrintTrait;
use starknet::account::Call;
use starknet::ClassHash;


#[starknet::interface]
trait IPriceContractTest<TState> {
    fn get_average_price(self: @TState, pool_key: PoolKey, seconds_ago: u32) -> u256;
    fn set_price_for_pool_key(ref self: TState, pool_key: PoolKey, seconds_ago: u32, price: u256);
}

type PoolKey = felt252;

#[starknet::contract]
mod PriceContractTest {
    use super::{IPriceContractTest, PoolKey};

    #[storage]
    struct Storage {
        mock_prices: LegacyMap::<(PoolKey, u32), u256>
    }


    #[external(v0)]
    impl ExternalMethods of IPriceContractTest<ContractState> {
        fn get_average_price(self: @ContractState, pool_key: PoolKey, seconds_ago: u32) -> u256 {
            self.mock_prices.read((pool_key, seconds_ago))
        }

        fn set_price_for_pool_key(
            ref self: ContractState, pool_key: PoolKey, seconds_ago: u32, price: u256
        ) {
            self.mock_prices.write((pool_key, seconds_ago), price);
        }
    }
}

