use array::{ArrayTrait, SpanTrait};
use core::result::ResultTrait;
use traits::{Into, TryInto};
use option::OptionTrait;

use braavos_account::signers::signer_type::{SignerType};
use braavos_account::signers::interface::{GetSignersResponse};

const SIG_LEN_STARK: usize = 2;
const PUBLIC_KEY_LEN_SECP256R1: usize = 4;
const RS_LEN_SECP256R1: usize = 4;


#[starknet::component]
mod SignerManagementComponent {
    use starknet::{SyscallResultTrait};
    use starknet::syscalls::get_execution_info_v2_syscall;
    use braavos_account::dwl::interface::IDwlInternal;
    use braavos_account::signers::interface;
    use braavos_account::signers::interface::{OwnerAdded, OwnerRemoved};
    use braavos_account::signers::signer_address_mgt::{
        remove_signer, remove_all_signers, get_first_signer, num_strong_signers, exists,
        any_strong_signer, get_signers
    };
    use braavos_account::utils::asserts::assert_self_caller;
    use super::{SignerType};
    use braavos_account::signers::signers::{
        Secp256r1PubKey, Secp256r1SignerMethodsTrait, StarkPubKey, StarkSignerMethodsTrait
    };

    mod Errors {
        const INVALID_ENTRYPOINT: felt252 = 'INVALID_ENTRYPOINT';
        const INVALID_ETD: felt252 = 'INVALID_ETD';
        const INVALID_MULTISIG_THRESH: felt252 = 'INVALID_MULTISIG_THRESHOLD';
        const INVALID_SIGNER: felt252 = 'INVALID_SIGNER';
        const NO_DEFERRED_REQUESTS: felt252 = 'NO_DEFERRED_REQUESTS';
        const SIGNER_NOT_EXISTS: felt252 = 'SIGNER_NOT_EXISTS';
    }

    mod Consts {
        const ACCOUNT_DEFAULT_ETD_SEC: u64 = 345600_u64; // 4 days == 24 * 4 * 60 * 60
        const ACCOUNT_MAX_ETD_SEC: u64 = 31536000_u64; // 365 days == 365 * 24 * 60 60
        const ACCOUNT_MIN_ETD_SEC: u64 = 86400_u64; // 1 day == 24 * 60 * 60
        const DEFERRED_REMOVE_SECP256R1_SIGNERS_SELECTOR: felt252 =
            selector!("deferred_remove_signers");
    }

    #[derive(Copy, Drop, Serde, starknet::Event, starknet::Store)]
    struct DeferredRemoveSignerRequest {
        expire_at: u64,
    }

    #[derive(Copy, Drop, Serde, starknet::Event)]
    struct DeferredRemoveSignerRequestCancelled {
        cancelled_deferred_request: DeferredRemoveSignerRequest,
    }

    #[derive(Copy, Drop, Serde, starknet::Event)]
    struct DeferredRemoveSignerRequestExpired {
        expired_deferred_request: DeferredRemoveSignerRequest,
    }

    #[storage]
    struct Storage {
        deferred_remove_signer_req: DeferredRemoveSignerRequest,
        deferred_req_time_delay: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        OwnerAdded: OwnerAdded,
        OwnerRemoved: OwnerRemoved,
        DeferredRemoveSignerRequest: DeferredRemoveSignerRequest,
        DeferredRemoveSignerRequestCancelled: DeferredRemoveSignerRequestCancelled,
        DeferredRemoveSignerRequestExpired: DeferredRemoveSignerRequestExpired,
    }


    fn _is_deferred_req_expired(
        deferred_req: DeferredRemoveSignerRequest, block_timestamp: u64
    ) -> bool {
        deferred_req.expire_at != 0 && deferred_req.expire_at < block_timestamp
    }

    #[embeddable_as(SignerManagementImplInternal)]
    impl InternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        +IDwlInternal<TContractState>,
        +interface::IMultisigInternal<TContractState>,
        +Drop<TContractState>,
    > of interface::ISignerManagementInternal<ComponentState<TContractState>> {
        /// Adds stark signer to storage
        #[inline(always)]
        fn _add_stark_signer_unsafe(
            ref self: ComponentState<TContractState>, stark_pub_key: StarkPubKey,
        ) {
            stark_pub_key.add_signer();
            self
                .emit(
                    OwnerAdded {
                        new_owner_guid: stark_pub_key.pub_key,
                        signer_type: SignerType::Stark,
                        signer_data: array![].span(),
                    }
                );
        }

        /// Adds strong secp256r1 signer to storage
        #[inline(always)]
        fn _add_secp256r1_signer_unsafe(
            ref self: ComponentState<TContractState>,
            secp256r1_signer: Secp256r1PubKey,
            signer_type: SignerType
        ) {
            secp256r1_signer.add_signer(signer_type);
            self
                .emit(
                    OwnerAdded {
                        new_owner_guid: secp256r1_signer.guid(),
                        signer_type: signer_type,
                        signer_data: array![
                            secp256r1_signer.pub_x.low.into(),
                            secp256r1_signer.pub_x.high.into(),
                            secp256r1_signer.pub_y.low.into(),
                            secp256r1_signer.pub_y.high.into()
                        ]
                            .span(),
                    }
                );
        }

        /// When removing signer not as an etd endpoint this function will remove existing
        /// deferred removal requests
        fn _handle_deferred_request_when_signer_removal(
            ref self: ComponentState<TContractState>, expired_etd: bool
        ) {
            // If we came from a non-etd removal flow, then send the cancel event
            if !expired_etd {
                let deferred_req: DeferredRemoveSignerRequest = self
                    .deferred_remove_signer_req
                    .read();
                if deferred_req.expire_at != 0 {
                    self
                        .emit(
                            DeferredRemoveSignerRequestCancelled {
                                cancelled_deferred_request: deferred_req
                            }
                        );
                }
            }
            // and in any case, whenever a signer is removed, cancel any pending request
            self.deferred_remove_signer_req.write(DeferredRemoveSignerRequest { expire_at: 0 });
        }

        /// Remove a specific strong secp256r1 signer from account
        fn _remove_secp256r1_signer_common_unsafe(
            ref self: ComponentState<TContractState>,
            expired_etd: bool,
            existing_guid: felt252,
            signer_type: SignerType
        ) {
            remove_signer(signer_type, existing_guid);
            self
                .emit(
                    OwnerRemoved {
                        removed_owner_guid: existing_guid, removed_signer_type: signer_type
                    }
                );
            self._handle_deferred_request_when_signer_removal(expired_etd);
        }

        /// Removes all strong signers from account
        fn _remove_all_secp256r1_signers_unsafe(
            ref self: ComponentState<TContractState>, expired_etd: bool
        ) {
            let mut removed_webauthn_signers = remove_all_signers(SignerType::Webauthn);
            let mut removed_hws_signers = remove_all_signers(SignerType::Secp256r1);

            loop {
                match removed_webauthn_signers.pop_front() {
                    Option::Some(guid) => {
                        self
                            .emit(
                                OwnerRemoved {
                                    removed_owner_guid: guid,
                                    removed_signer_type: SignerType::Webauthn
                                }
                            );
                    },
                    Option::None(_) => { break; }
                };
            };
            loop {
                match removed_hws_signers.pop_front() {
                    Option::Some(guid) => {
                        self
                            .emit(
                                OwnerRemoved {
                                    removed_owner_guid: guid,
                                    removed_signer_type: SignerType::Secp256r1
                                }
                            );
                    },
                    Option::None(_) => { break; }
                };
            };

            self._handle_deferred_request_when_signer_removal(expired_etd);
        }

        /// Checks whether a deferred signer removal request has expired and if so removes all
        /// strong signers. After removing all strong signers it also removes multisig thresholds
        /// and any existing withdrawal limits.
        fn _apply_deferred_remove_signers_req(
            ref self: ComponentState<TContractState>, block_timestamp: u64
        ) {
            let deferred_req = self.deferred_remove_signer_req.read();
            let mut mut_contract = self.get_contract_mut();
            if _is_deferred_req_expired(deferred_req, block_timestamp) {
                self
                    .emit(
                        DeferredRemoveSignerRequestExpired {
                            expired_deferred_request: deferred_req
                        }
                    );
                // Deferred removal removes all strong signers so multisig and DWL should be disabled
                mut_contract._set_multisig_threshold_inner(multisig_threshold: 0, num_signers: 1);
                self._remove_all_secp256r1_signers_unsafe(expired_etd: true);
                if mut_contract._get_withdrawal_limit_low_inner() != 0 {
                    mut_contract._set_withdrawal_limit_low_inner(0, 0, 0, false);
                }
                if mut_contract._get_withdrawal_limit_high_inner() != 0 {
                    mut_contract._set_withdrawal_limit_high_inner(0, 0, 0, false, false);
                }
            }
        }
    }

    #[embeddable_as(SignerManagementImpl)]
    impl ExternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        +IDwlInternal<TContractState>,
        +interface::IMultisig<TContractState>,
        +interface::IMultisigInternal<TContractState>,
        +Drop<TContractState>,
    > of interface::ISignerManagement<ComponentState<TContractState>> {
        /// Fetches the stark public key. Note there can only be one stark signer in account.
        fn get_public_key(self: @ComponentState<TContractState>) -> felt252 {
            get_first_signer(SignerType::Stark)
        }

        /// Fetches all signers stored in account
        fn get_signers(self: @ComponentState<TContractState>) -> interface::GetSignersResponse {
            get_signers()
        }

        /// Adds a strong secp256r1 signer to account. Validates the public key and updates multisig
        /// threshold if needed.
        /// @param secp256r1_signer - public key of signer
        /// @param signer_type - can be a hw signer or webauthn, both use secp256r1 curve
        /// @param multisig_threshold - when adding a strong signer, multisig can be set
        fn add_secp256r1_signer(
            ref self: ComponentState<TContractState>,
            secp256r1_signer: Secp256r1PubKey,
            signer_type: SignerType,
            multisig_threshold: usize
        ) {
            assert_self_caller();
            assert(
                signer_type == SignerType::Secp256r1 || signer_type == SignerType::Webauthn,
                Errors::INVALID_SIGNER
            );
            assert(
                Secp256r1SignerMethodsTrait::assert_valid_point(@secp256r1_signer),
                Errors::INVALID_SIGNER
            );
            self._add_secp256r1_signer_unsafe(secp256r1_signer, signer_type);
            let mut mut_contract = self.get_contract_mut();
            let curr_multisig_thresh = mut_contract.get_multisig_threshold();
            if (multisig_threshold != curr_multisig_thresh) {
                mut_contract
                    ._set_multisig_threshold_inner(
                        multisig_threshold, num_signers: num_strong_signers() + 1
                    );
            }
        }

        /// removes strong secp256r1 signer from account.
        /// @param guid - represents the hash of the signer's public key
        /// @param signer_type - type of the signer to remove
        /// @param multisig_threshold - when removing strong signer, multisig threshold can be changed
        fn remove_secp256r1_signer(
            ref self: ComponentState<TContractState>,
            guid: felt252,
            signer_type: SignerType,
            multisig_threshold: usize
        ) {
            assert_self_caller();
            let mut mut_contract = self.get_contract_mut();
            assert(
                signer_type == SignerType::Secp256r1 || signer_type == SignerType::Webauthn,
                Errors::INVALID_SIGNER
            );
            assert(exists(signer_type, guid), Errors::SIGNER_NOT_EXISTS);

            self
                ._remove_secp256r1_signer_common_unsafe(
                    expired_etd: false, existing_guid: guid, signer_type: signer_type
                );

            let num_of_strong_signers = num_strong_signers();
            if num_of_strong_signers == 0 {
                assert(multisig_threshold == 0, Errors::INVALID_MULTISIG_THRESH);
                mut_contract._set_multisig_threshold_inner(multisig_threshold: 0, num_signers: 1);
                if mut_contract._get_withdrawal_limit_low_inner() != 0 {
                    mut_contract._set_withdrawal_limit_low_inner(0, 0, 0, false);
                }
                if mut_contract._get_withdrawal_limit_high_inner() != 0 {
                    mut_contract._set_withdrawal_limit_high_inner(0, 0, 0, false, false);
                }
            } else {
                // Note the + 1 represents the stark signer
                mut_contract
                    ._set_multisig_threshold_inner(
                        multisig_threshold, num_signers: num_strong_signers() + 1
                    );
                if multisig_threshold == 0 && mut_contract._get_withdrawal_limit_high_inner() != 0 {
                    mut_contract._set_withdrawal_limit_high_inner(0, 0, 0, false, false);
                }
            }
        }

        /// Swaps strong secp256r1 signer with another one in account
        /// @param secp256r1_signer - public key of new signer
        /// @param existing_guid - represents the hash of the public key of the removed signer
        /// @param signer_type - type of the signer to remove. New signer must have the same type
        fn change_secp256r1_signer(
            ref self: ComponentState<TContractState>,
            secp256r1_signer: Secp256r1PubKey,
            existing_guid: felt252,
            signer_type: SignerType
        ) {
            assert_self_caller();
            assert(
                signer_type == SignerType::Secp256r1 || signer_type == SignerType::Webauthn,
                Errors::INVALID_SIGNER
            );
            assert(exists(signer_type, existing_guid), Errors::SIGNER_NOT_EXISTS);
            assert(
                Secp256r1SignerMethodsTrait::assert_valid_point(@secp256r1_signer),
                Errors::INVALID_SIGNER
            );
            self
                ._remove_secp256r1_signer_common_unsafe(
                    expired_etd: false, existing_guid: existing_guid, signer_type: signer_type
                );
            self._add_secp256r1_signer_unsafe(secp256r1_signer, signer_type);
        }

        /// Set the delay of deferred removal request
        fn set_execution_time_delay(ref self: ComponentState<TContractState>, time_delay: u64) {
            assert_self_caller();
            assert(
                time_delay >= Consts::ACCOUNT_MIN_ETD_SEC
                    && time_delay <= Consts::ACCOUNT_MAX_ETD_SEC,
                Errors::INVALID_ETD
            );
            let deferred_req: DeferredRemoveSignerRequest = self.deferred_remove_signer_req.read();
            assert(deferred_req.expire_at == 0, Errors::INVALID_ENTRYPOINT);
            self.deferred_req_time_delay.write(time_delay);
        }

        /// Fetches the delay of a deferred removal request
        fn get_execution_time_delay(self: @ComponentState<TContractState>) -> u64 {
            let account_etd = self.deferred_req_time_delay.read();
            if account_etd != 0 {
                account_etd
            } else {
                Consts::ACCOUNT_DEFAULT_ETD_SEC
            }
        }

        /// Fetches existing request of signer deferred removal
        fn get_deferred_remove_signers(
            self: @ComponentState<TContractState>
        ) -> DeferredRemoveSignerRequest {
            self.deferred_remove_signer_req.read()
        }

        /// Generates deferred removal request. This request on expiry will remove all strong
        /// signers from account.
        fn deferred_remove_signers(ref self: ComponentState<TContractState>) {
            assert_self_caller();

            assert(any_strong_signer(), Errors::INVALID_ENTRYPOINT);

            let deferred_req: DeferredRemoveSignerRequest = self.deferred_remove_signer_req.read();
            assert(deferred_req.expire_at == 0, Errors::INVALID_ENTRYPOINT);

            let exec_info = get_execution_info_v2_syscall().unwrap_syscall();
            let account_etd = self.deferred_req_time_delay.read();
            let deferred_req_expiry = exec_info.unbox().block_info.unbox().block_timestamp
                + if account_etd != 0 {
                    account_etd
                } else {
                    Consts::ACCOUNT_DEFAULT_ETD_SEC
                };
            self.emit(DeferredRemoveSignerRequest { expire_at: deferred_req_expiry });
            self
                .deferred_remove_signer_req
                .write(DeferredRemoveSignerRequest { expire_at: deferred_req_expiry });
        }

        /// Cancels any existing deferred removal request
        fn cancel_deferred_remove_signers(ref self: ComponentState<TContractState>) {
            assert_self_caller();
            let deferred_req: super::SignerManagementComponent::DeferredRemoveSignerRequest = self
                .deferred_remove_signer_req
                .read();
            assert(deferred_req.expire_at != 0, Errors::NO_DEFERRED_REQUESTS);
            self
                .emit(
                    DeferredRemoveSignerRequestCancelled {
                        cancelled_deferred_request: deferred_req
                    }
                );
            self.deferred_remove_signer_req.write(DeferredRemoveSignerRequest { expire_at: 0, });
        }
    }
}
