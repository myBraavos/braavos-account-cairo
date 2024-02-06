use starknet::ClassHash;

const IUPGRADABLE_ID: felt252 = 0x22e2da9785c8e117a9ee8b59a880f5c634ef5a17cd631b65b0785f6367feb8f;

#[starknet::interface]
trait IUpgradable<TState> {
    fn upgrade(ref self: TState, upgrade_to: ClassHash);
}

const ISTORAGE_MIGRATION_ID: felt252 =
    0x11b3a49796b9a26cb8541143be5abfd2522a0769ad2f464915a39a4910b908b;

#[starknet::interface]
trait IStorageMigration<TState> {
    fn migrate_storage(ref self: TState, from_version: felt252);
}
