/// # MoaSignerManagement Component
///
/// The MoaSignerManagement Component implements the management of signers
/// within MOA. It provides methods for adding and removing signers,
/// checking their status, and managing the multisignature threshold.

#[starknet::component]
mod MoaSignerManagement {
    use core::dict::Felt252DictTrait;
    use braavos_account::signers::interface::{
        IMoaSignManagementInternal, IMoaSignManagementExternal, IMultisig, IMultisigInternal,
        OwnerAdded, OwnerRemoved, GetMoaSignersResponse
    };
    use starknet::{ContractAddress, contract_address_const, TryInto, Into};
    use core::array::ArrayTrait;
    use braavos_account::utils::asserts::{assert_self_caller};
    use braavos_account::utils::arrays::span_to_dict;
    use braavos_account::signers::signers::{MoaSigner, MoaSignerMethods};
    use braavos_account::signers::signer_address_mgt::{
        get_signers_by_type, remove_signer, add_signer, exists
    };
    use braavos_account::signers::signer_type::SignerType;

    mod Errors {
        const NO_SIGNERS: felt252 = 'NO_SIGNERS';
        const DUPLICATE_SIGNER: felt252 = 'DUPLICATE_SIGNER';
        const UNKNOWN_SIGNER: felt252 = 'UNKNOWN_SIGNER';
    }

    #[storage]
    struct Storage {}

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        OwnerAdded: OwnerAdded,
        OwnerRemoved: OwnerRemoved,
    }

    #[embeddable_as(MoaSignerManagementImpl)]
    impl MoaSignManagementExternal<
        TContractState,
        +HasComponent<TContractState>,
        +Drop<TContractState>,
        +IMultisigInternal<TContractState>,
        +IMultisig<TContractState>,
    > of IMoaSignManagementExternal<ComponentState<TContractState>> {
        /// @param signer The account address and public key of a signer
        /// @return True If the signer exists
        fn is_signer(self: @ComponentState<TContractState>, signer: MoaSigner) -> bool {
            signer.exists().is_some()
        }

        /// @return The amount of signers
        fn get_signers_len(self: @ComponentState<TContractState>) -> usize {
            get_signers_by_type(SignerType::MOA).len()
        }

        /// @return Array with the list of signers guids
        fn get_signers(self: @ComponentState<TContractState>) -> GetMoaSignersResponse {
            GetMoaSignersResponse { moa: get_signers_by_type(SignerType::MOA) }
        }

        /// @param signers An array of pairs representing the external
        /// signers to be added
        /// @param threshold New threshold value
        /// @emit Event about adding a new signer
        ///
        /// Panic if threshold is invalid after changes
        /// Panic if signer already added
        fn add_external_signers(
            ref self: ComponentState<TContractState>,
            signers: Array<(ContractAddress, felt252)>,
            threshold: usize
        ) {
            assert_self_caller();
            self._add_signers(signers, threshold);
        }

        /// @param signer_guids An array of GUIDs of signers to be removed
        /// @param threshold New threshold value
        /// @emit Event about removed signer
        ///
        /// Panic if threshold is invalid after changes
        /// Panic of deleting non-existent signer
        fn remove_external_signers(
            ref self: ComponentState<TContractState>,
            mut signer_guids: Span<felt252>,
            threshold: usize
        ) {
            assert_self_caller();
            span_to_dict(signer_guids, assert_unique: true);

            let remove_signers_len: usize = signer_guids.len();
            let existing_signers: Array<felt252> = get_signers_by_type(SignerType::MOA);
            let existing_signers_len: usize = existing_signers.len();
            let mut existing_signers_dict = span_to_dict(
                existing_signers.span(), assert_unique: false
            );
            let resulting_signers_len: usize = existing_signers_len - remove_signers_len;

            assert(resulting_signers_len > 0, Errors::NO_SIGNERS);

            loop {
                match signer_guids.pop_front() {
                    Option::Some(guid) => {
                        assert(existing_signers_dict.get(*guid), Errors::UNKNOWN_SIGNER);
                        remove_signer(SignerType::MOA, *guid);
                        self
                            .emit(
                                OwnerRemoved {
                                    removed_owner_guid: *guid, removed_signer_type: SignerType::MOA
                                }
                            );
                    },
                    Option::None => { break; },
                };
            };

            self._update_threshold(threshold, resulting_signers_len);
        }
    }

    #[embeddable_as(MoaSignerManagementInternalImpl)]
    impl MoaSignManagementInternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        +Drop<TContractState>,
        +IMultisigInternal<TContractState>,
        +IMultisig<TContractState>,
    > of IMoaSignManagementInternal<ComponentState<TContractState>> {
        /// Updates threshold if its value has changed
        fn _update_threshold(
            ref self: ComponentState<TContractState>, threshold: usize, num_signers: usize
        ) {
            let mut mut_contract = self.get_contract_mut();
            mut_contract._set_multisig_threshold_inner(threshold, num_signers);
        }

        /// Internal implementation for adding
        fn _add_signers(
            ref self: ComponentState<TContractState>,
            mut signers: Array<(ContractAddress, felt252)>,
            threshold: usize
        ) {
            let append_signers_len: usize = signers.len();
            let existing_signers: Array<felt252> = get_signers_by_type(SignerType::MOA);
            let existing_signers_len: usize = existing_signers.len();
            let mut existing_signers_dict = span_to_dict(
                existing_signers.span(), assert_unique: false
            );
            let resulting_signers_len: usize = append_signers_len + existing_signers_len;

            assert(resulting_signers_len > 0, Errors::NO_SIGNERS);

            let mut address_dup_tracker: Felt252Dict<bool> = Default::default();
            // Write new signers
            loop {
                match signers.pop_front() {
                    Option::Some((
                        address, pub_key
                    )) => {
                        assert(
                            pub_key != 0 && address != contract_address_const::<0>(),
                            'INVALID_SIGNER'
                        );
                        let moa_signer = MoaSigner { pub_key: pub_key, address: address };
                        let guid = moa_signer.guid();
                        assert(!existing_signers_dict.get(guid), Errors::DUPLICATE_SIGNER);
                        assert(
                            address_dup_tracker.get(address.into()) == false,
                            Errors::DUPLICATE_SIGNER
                        );
                        address_dup_tracker.insert(address.into(), true);
                        add_signer(SignerType::MOA, guid);
                        self
                            .emit(
                                OwnerAdded {
                                    new_owner_guid: guid,
                                    signer_type: SignerType::MOA,
                                    signer_data: array![address.into(), pub_key].span(),
                                }
                            );
                    },
                    Option::None => { break; },
                };
            };

            self._update_threshold(threshold, resulting_signers_len);
        }
    }
}
