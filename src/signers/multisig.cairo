#[starknet::component]
mod MultisigComponent {
    use braavos_account::signers::signer_address_mgt::{
        get_signers, get_signers_by_type, SignerType
    };
    use braavos_account::signers::interface;
    use braavos_account::utils::asserts::assert_self_caller;
    use braavos_account::dwl::interface::IDwlInternal;

    mod Errors {
        const INVALID_MULTISIG_THRESH: felt252 = 'INVALID_MULTISIG_THRESHOLD';
    }

    #[derive(Drop, starknet::Event)]
    struct MultisigSet {
        multisig_threshold: usize,
    }

    #[storage]
    struct Storage {
        multisig_threshold: usize,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        MultisigSet: MultisigSet,
    }

    #[embeddable_as(MultisigImplInternal)]
    impl InternalImpl<
        TContractState, +HasComponent<TContractState>, +Drop<TContractState>,
    > of interface::IMultisigInternal<ComponentState<TContractState>> {
        #[inline(always)]
        fn _set_multisig_threshold_inner(
            ref self: ComponentState<TContractState>, multisig_threshold: usize, num_signers: usize
        ) {
            assert(
                multisig_threshold == 0
                    || (num_signers >= 2
                        && (multisig_threshold >= 2 && multisig_threshold <= num_signers)),
                Errors::INVALID_MULTISIG_THRESH
            );
            self.emit(MultisigSet { multisig_threshold: multisig_threshold });
            self.multisig_threshold.write(multisig_threshold);
        }
    }

    #[embeddable_as(MultisigImpl)]
    impl ExternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        +Drop<TContractState>,
        +IDwlInternal<TContractState>,
        +interface::ISignerChangeManagementInternalImpl<TContractState>,
    > of interface::IMultisig<ComponentState<TContractState>> {
        /// Sets the value of multisig threshold in storage. If a value is over 1 then
        /// the user would need two or more signers to sign a transaction.
        /// A value of 0 removes multisig requirements from account and this entails
        /// removal of high withdrawal limit if exists. The inner function is responsible
        /// for other invariants
        fn set_multisig_threshold(
            ref self: ComponentState<TContractState>, multisig_threshold: usize
        ) {
            assert_self_caller();
            let all_signers = get_signers();
            let num_signers = all_signers.stark.len()
                + all_signers.secp256r1.len()
                + all_signers.webauthn.len();

            self._set_multisig_threshold_inner(multisig_threshold, num_signers);

            let mut mut_contract = self.get_contract_mut();
            if multisig_threshold == 0 && mut_contract._get_withdrawal_limit_high_inner() != 0 {
                mut_contract._set_withdrawal_limit_high_inner(0, 0, 0, false, false);
            }
            mut_contract._increment_signer_change_index();
        }

        fn get_multisig_threshold(self: @ComponentState<TContractState>) -> usize {
            self.multisig_threshold.read()
        }
    }

    #[embeddable_as(MultisigMoaImpl)]
    impl ExternalMoaImpl<
        TContractState, +HasComponent<TContractState>, +Drop<TContractState>,
    > of interface::IMultisig<ComponentState<TContractState>> {
        /// @param multisig_threshold New threshold value
        /// Sets an adjusted threshold for the number of signatures required to
        /// validate a transaction
        fn set_multisig_threshold(
            ref self: ComponentState<TContractState>, multisig_threshold: usize
        ) {
            assert_self_caller();
            let num_moa_signers = get_signers_by_type(SignerType::MOA).len();
            self._set_multisig_threshold_inner(multisig_threshold, num_moa_signers);
        }

        /// @return Adjusted threshold number of signatures required
        /// for transaction confirmation
        fn get_multisig_threshold(self: @ComponentState<TContractState>) -> usize {
            self.multisig_threshold.read()
        }
    }
}

