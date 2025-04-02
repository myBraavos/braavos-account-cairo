#[starknet::component]
mod UpgradableComponent {
    use braavos_account::account::interface::{IBraavosAccount, IGetVersion, ISRC6_ID};
    use braavos_account::introspection::interface::{
        ISRC5WithCamelCaseDispatcherTrait, ISRC5WithCamelCaseLibraryDispatcher,
    };
    use braavos_account::signers::interface::{
        IMoaSignManagementInternal, IMultisigInternal, ISignerManagementInternal,
    };
    use braavos_account::signers::signer_address_mgt;
    use braavos_account::signers::signers::{Secp256r1PubKey, SignerType, StarkPubKey};
    use braavos_account::upgradable::interface::{
        ISTORAGE_MIGRATION_ID, IStorageMigration, IStorageMigrationDispatcherTrait,
        IStorageMigrationLibraryDispatcher, IUpgradable,
    };
    use braavos_account::utils::asserts::assert_self_caller;
    use starknet::{ClassHash, ContractAddress, SyscallResultTrait, replace_class_syscall};

    mod Errors {
        const INVALID_CLASS: felt252 = 'INVALID_CLASS_HASH';
        const INVALID_STARK_PUB_KEY: felt252 = 'INVALID_STARK_PUB_KEY';
        const INVALID_STORAGE_MIGRATE: felt252 = 'INVALID_STORAGE_MIGRATE';
        const NOT_SRC6: felt252 = 'CLASS_HASH_NOT_SRC6';
    }

    mod Consts {
        const LEGACY_STORAGE_ADDR_SIGNERS_KECCAK: felt252 = selector!("Account_signers");
        const LEGACY_STORAGE_ADDR_SIGNERS_MAX_IDX: felt252 = selector!("Account_signers_max_index");
        const LEGACY_STORAGE_ADDR_STARK_SIGNER: felt252 =
            0x1f23302c120008f28b62f70efc67ccd75cfe0b9631d77df231d78b0538dcd8f;
        const LEGACY_STORAGE_ADDR_NUM_HW_SIGNERS: felt252 = selector!(
            "Account_signers_num_hw_signers",
        );
        const LEGACY_STORAGE_ADDR_NUM_EXT_SIGNERS: felt252 = selector!(
            "Signers_num_ext_account_signers",
        );
        const LEGACY_STORAGE_ADDR_MULTISIG_NUM_SIGNERS: felt252 = selector!("Multisig_num_signers");
    }

    #[storage]
    struct Storage {}

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        Upgraded: Upgraded,
    }

    #[derive(Drop, starknet::Event)]
    struct Upgraded {
        #[key]
        class_hash: ClassHash,
    }

    #[embeddable_as(UpgradableImpl)]
    impl ExternalUpgradableImpl<
        TContractState,
        +HasComponent<TContractState>,
        +IGetVersion<TContractState>,
        +Drop<TContractState>,
    > of IUpgradable<ComponentState<TContractState>> {
        /// Upgrades account to the given class hash
        fn upgrade(ref self: ComponentState<TContractState>, upgrade_to: ClassHash) {
            assert_self_caller();

            assert(upgrade_to.is_zero() == false, Errors::INVALID_CLASS);

            let supports_src6 = ISRC5WithCamelCaseLibraryDispatcher { class_hash: upgrade_to }
                .supports_interface(ISRC6_ID);
            assert(supports_src6, Errors::NOT_SRC6);

            let supports_storage_migration = ISRC5WithCamelCaseLibraryDispatcher {
                class_hash: upgrade_to,
            }
                .supports_interface(ISTORAGE_MIGRATION_ID);
            if supports_storage_migration {
                IStorageMigrationLibraryDispatcher { class_hash: upgrade_to }
                    .migrate_storage(self.get_contract().get_version());
            }

            self.emit(Upgraded { class_hash: upgrade_to });
            replace_class_syscall(upgrade_to).unwrap_syscall();
        }
    }

    #[embeddable_as(StorageMigrationImpl)]
    impl ExternalStorageMigratableImpl<
        TContractState,
        +HasComponent<TContractState>,
        +ISignerManagementInternal<TContractState>,
        +IMultisigInternal<TContractState>,
        +Drop<TContractState>,
    > of IStorageMigration<ComponentState<TContractState>> {
        /// Migrates storage from the previous account version to the current.
        /// Will insert existing signers into the correct signer list by type and set the
        /// multisig value
        fn migrate_storage(ref self: ComponentState<TContractState>, from_version: felt252) {
            assert_self_caller();
            let mut mut_contract = self.get_contract_mut();
            if from_version == '000.000.011' {
                assert(
                    signer_address_mgt::any(SignerType::Stark) == false,
                    Errors::INVALID_STORAGE_MIGRATE,
                );
                let stark_pub_key = starknet::Store::<
                    felt252,
                >::read(
                    0_u32,
                    starknet::storage_base_address_from_felt252(
                        Consts::LEGACY_STORAGE_ADDR_STARK_SIGNER,
                    ),
                )
                    .unwrap();
                assert(stark_pub_key != 0, Errors::INVALID_STARK_PUB_KEY);

                mut_contract._add_stark_signer_unsafe(StarkPubKey { pub_key: stark_pub_key });
                let have_secp256r1_signer = starknet::Store::<
                    felt252,
                >::read(
                    0_u32,
                    starknet::storage_base_address_from_felt252(
                        Consts::LEGACY_STORAGE_ADDR_NUM_HW_SIGNERS,
                    ),
                )
                    .unwrap();
                if have_secp256r1_signer != 0 {
                    let secp256r1_signer_idx = starknet::Store::<
                        felt252,
                    >::read(
                        0_u32,
                        starknet::storage_base_address_from_felt252(
                            Consts::LEGACY_STORAGE_ADDR_SIGNERS_MAX_IDX,
                        ),
                    )
                        .unwrap();
                    let secp256r1_signer_base_addr = starknet::storage_base_address_from_felt252(
                        hash::LegacyHash::<
                            felt252,
                        >::hash(Consts::LEGACY_STORAGE_ADDR_SIGNERS_KECCAK, secp256r1_signer_idx),
                    );

                    let (pub_x_low, pub_x_high, pub_y_low, pub_y_high) = starknet::Store::<
                        (felt252, felt252, felt252, felt252),
                    >::read(0_u32, secp256r1_signer_base_addr)
                        .unwrap();

                    mut_contract
                        ._add_secp256r1_signer_unsafe(
                            Secp256r1PubKey {
                                pub_x: u256 {
                                    low: pub_x_low.try_into().unwrap(),
                                    high: pub_x_high.try_into().unwrap(),
                                },
                                pub_y: u256 {
                                    low: pub_y_low.try_into().unwrap(),
                                    high: pub_y_high.try_into().unwrap(),
                                },
                            },
                            SignerType::Secp256r1,
                        );

                    let multisig_num_signers: usize = starknet::Store::<
                        usize,
                    >::read(
                        0_u32,
                        starknet::storage_base_address_from_felt252(
                            Consts::LEGACY_STORAGE_ADDR_MULTISIG_NUM_SIGNERS,
                        ),
                    )
                        .unwrap();
                    if multisig_num_signers != 0 {
                        mut_contract._set_multisig_threshold_inner(multisig_num_signers, 2);
                    }
                }
            }
        }
    }


    #[embeddable_as(StorageMigrationMOAImpl)]
    impl ExternalStorageMigratableMOAImpl<
        TContractState,
        +HasComponent<TContractState>,
        +IMoaSignManagementInternal<TContractState>,
        +IMultisigInternal<TContractState>,
        +Drop<TContractState>,
    > of IStorageMigration<ComponentState<TContractState>> {
        /// Migrates storage from the previous account version to the current.
        /// Will insert existing signers into the correct signer list by type and set the
        /// multisig value
        fn migrate_storage(ref self: ComponentState<TContractState>, from_version: felt252) {
            assert_self_caller();
            let mut mut_contract = self.get_contract_mut();
            if from_version == '000.000.011' || from_version == '000.000.012' {
                assert(
                    signer_address_mgt::any(SignerType::MOA) == false,
                    Errors::INVALID_STORAGE_MIGRATE,
                );
                let have_moa_signers = starknet::Store::<
                    felt252,
                >::read(
                    0_u32,
                    starknet::storage_base_address_from_felt252(
                        Consts::LEGACY_STORAGE_ADDR_NUM_EXT_SIGNERS,
                    ),
                )
                    .unwrap();

                assert(have_moa_signers != 0, Errors::INVALID_STORAGE_MIGRATE);

                let signer_max_idx: usize = starknet::Store::<
                    usize,
                >::read(
                    0_u32,
                    starknet::storage_base_address_from_felt252(
                        Consts::LEGACY_STORAGE_ADDR_SIGNERS_MAX_IDX,
                    ),
                )
                    .unwrap();

                let mut i = 1; // in legacy MOA account, deployment stark signer was at index 0
                let mut legacy_signers: Array<(ContractAddress, felt252)> = array![];
                loop {
                    if i > signer_max_idx {
                        break;
                    }

                    let signer_base_addr = starknet::storage_base_address_from_felt252(
                        hash::LegacyHash::<
                            felt252,
                        >::hash(Consts::LEGACY_STORAGE_ADDR_SIGNERS_KECCAK, i.into()),
                    );
                    let (address, stark_pub_key) = starknet::Store::<
                        (felt252, felt252),
                    >::read(0_u32, signer_base_addr)
                        .unwrap();
                    let signer_type = starknet::Store::<
                        felt252,
                    >::read_at_offset(0_u32, signer_base_addr, 4)
                        .unwrap();

                    if signer_type == SignerType::MOA.into() {
                        legacy_signers.append((address.try_into().unwrap(), stark_pub_key));
                    } else {
                        assert(
                            signer_type == SignerType::Empty.into(),
                            Errors::INVALID_STORAGE_MIGRATE,
                        );
                    }
                    i += 1;
                }
                let multisig_num_signers: usize = starknet::Store::<
                    usize,
                >::read(
                    0_u32,
                    starknet::storage_base_address_from_felt252(
                        Consts::LEGACY_STORAGE_ADDR_MULTISIG_NUM_SIGNERS,
                    ),
                )
                    .unwrap();
                assert(multisig_num_signers >= 2, Errors::INVALID_STORAGE_MIGRATE);

                mut_contract._add_signers(legacy_signers, multisig_num_signers);
            }
        }
    }
}

