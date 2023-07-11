%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.hash_state import (
    hash_init,
    hash_update,
    hash_update_single,
    hash_update_with_hashchain,
    hash_finalize,
)
from starkware.cairo.common.math import (
    assert_le,
    assert_not_zero,
)
from starkware.cairo.common.math_cmp import (
    is_le,
    is_le_felt,
    is_not_zero,
)
from starkware.starknet.common.constants import INVOKE_HASH_PREFIX
from starkware.starknet.common.syscalls import (
    emit_event,
    get_block_number,
    get_block_timestamp,
    get_contract_address,
    get_tx_info,
    storage_read,
    storage_write,
    TxInfo,
)

from src.account.library import (
    Account,
    AccountCallArray,
    Call,
)
from src.signers.library import (
    Account_signers_num_hw_signers,
    IndexedSignerModel,
    Signers,
    Signers_num_ext_account_signers,
)
from src.utils.constants import (
    ACCOUNT_DEFAULT_EXECUTION_TIME_DELAY_SEC,
    ASSERT_EXPECTED_MAX_FEE_SELECTOR,
    DISABLE_MULTISIG_WITH_ETD_SELECTOR,
    MULTISIG_MOA_MAX_VALIDATE_FEE_FOR_PRE_EXEC_SIGNER,
    MULTISIG_PENDING_TXN_EXPIRY_BLOCK_NUM,
    MULTISIG_PENDING_TXN_MOA_EXPIRY_BLOCK_NUM,
    MULTISIG_PENDING_TXN_EXPIRY_SEC,
    MULTISIG_PENDING_TXN_MOA_EXPIRY_SEC,
    REMOVE_SIGNER_WITH_ETD_SELECTOR,
    SIGN_PENDING_MULTISIG_TXN_SELECTOR,
    SIGNER_TYPE_STARK,
    SIGNER_TYPE_UNUSED,
    TX_VERSION_1_EST_FEE
)

// Structs
struct PendingMultisigTransaction {
    transaction_hash: felt,
    expire_at_sec: felt,
    expire_at_block_num: felt,
    // deprecated
    is_disable_multisig_transaction: felt,
    // Pointer to the start address of signers storage
    signers: felt,
}

struct DeferredMultisigDisableRequest {
    expire_at: felt,
}

// Events
@event
func MultisigDisableRequest(request: DeferredMultisigDisableRequest) {
}

@event
func MultisigDisableRequestCancelled(request: DeferredMultisigDisableRequest) {
}

@event
func MultisigSet(num_signers: felt) {
}

@event
func MultisigDisabled() {
}

// We dont use @event because we want more than 1 key in the events
const MultisigPendingTransactionSelector =  1076481841203195901192246052515948214390765227783939297815575703989242392013;
const MultisigPendingTransactionSignedSelector = 77148960833872616285480930780499646942191152514328985919763224338929016653;

// Storage
@storage_var
func Multisig_num_signers() -> (res: felt) {
}

@storage_var
func Multisig_pending_transaction() -> (res: PendingMultisigTransaction) {
}

@storage_var
func Multisig_deferred_disable_request() -> (res: DeferredMultisigDisableRequest) {
}

namespace Multisig {
    func set_multisig{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(num_multisig_signers: felt, num_account_signers: felt) -> () {

        with_attr error_message("Multisig: multisig threshold must be at most the number of signers in the account") {
            assert_le(num_multisig_signers, num_account_signers);
        }

        with_attr error_message("Multisig: multisig threshold must be at least 2") {
            assert_le(2, num_multisig_signers);
        }
        Multisig_num_signers.write(num_multisig_signers);
        MultisigSet.emit(num_multisig_signers);

        return ();
    }

    func get_multisig_num_signers{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }() -> (multisig_num_signers: felt) {
        let (multisig_signers) = Multisig_num_signers.read();

        return (multisig_num_signers = multisig_signers);
    }

    func multisig_execute{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(
        call_array_len: felt, call_array: AccountCallArray*,
        tx_info: TxInfo*
    ) -> (multisig_deferred: felt) {
        alloc_locals;
        let (multisig_num_signers) = Multisig_num_signers.read();
        let (num_ext_account_signers) = Signers_num_ext_account_signers.read();
        tempvar have_ext_account_signers = is_not_zero(num_ext_account_signers);

        if (multisig_num_signers == 0) {
            return (multisig_deferred=FALSE);
        }
        let (local multi_signers_len, local multi_signers) = Signers.resolve_signers_from_sig(
            tx_info.signature_len, tx_info.signature
        );

        // sig contains multiple signers
        // already validated in multisig_validate, Signers.is_valid_sig* and Signers.resolve_signers_from_sig
        if (is_le(2, multi_signers_len) == TRUE) {
            return (multisig_deferred=FALSE);
        } else {
            let range_check_ptr = range_check_ptr;
            let syscall_ptr = syscall_ptr;
        }

        let (block_timestamp) = get_block_timestamp();
        let (block_num) = get_block_number();
        let current_signer = multi_signers[0];

        // selector values below should be handled in current execute flow and not be deferred
        // since we are checking on selector, only one of these will be 1 or all 0
        let (non_deferred_selector, _, _, _) = is_non_deferred_selector_in_multisig(call_array[0].to, call_array[0].selector);
        if (non_deferred_selector == TRUE) {
            return (multisig_deferred=FALSE);
        }

        // Create / Override pending txn
        tempvar expire_at_sec = (
            (1 - have_ext_account_signers) * (block_timestamp + MULTISIG_PENDING_TXN_EXPIRY_SEC) +
            have_ext_account_signers * (block_timestamp + MULTISIG_PENDING_TXN_MOA_EXPIRY_SEC)
        );
        tempvar expire_at_block_num = (
            (1 - have_ext_account_signers) * (block_num + MULTISIG_PENDING_TXN_EXPIRY_BLOCK_NUM) +
            have_ext_account_signers * (block_num + MULTISIG_PENDING_TXN_MOA_EXPIRY_BLOCK_NUM)
        );

        let pendingTxn = PendingMultisigTransaction(
                transaction_hash = tx_info.transaction_hash,
                expire_at_sec = expire_at_sec,
                expire_at_block_num = expire_at_block_num,
                is_disable_multisig_transaction = 0,
                signers = current_signer.index,
        );
        Multisig_pending_transaction.write(pendingTxn);
        let (local signers_address_base) = Multisig_pending_transaction.addr();
        let signers_address_base = signers_address_base + 4;
        pending_multisig_transaction_signers_wipe(
            signers_address_base, 1, multisig_num_signers - 1,
        );

        let (local pendingTxnEvtKeys: felt*) = alloc();
        assert [pendingTxnEvtKeys]  = MultisigPendingTransactionSelector;
        assert [pendingTxnEvtKeys + 1] = current_signer.index;
        let (local pendingTxnEvtData: felt*) = alloc();
        assert [pendingTxnEvtData] = tx_info.transaction_hash;
        assert [pendingTxnEvtData + 1] = expire_at_sec;
        assert [pendingTxnEvtData + 2] = expire_at_block_num;
        emit_event(2, pendingTxnEvtKeys, 3, pendingTxnEvtData);
        return (multisig_deferred=TRUE);
    }

    func get_pending_multisig_transaction{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }() -> (
        pending_multisig_transaction: PendingMultisigTransaction,
        signer_ids_len: felt,
        signer_ids: felt*,

    ) {
        alloc_locals;

        let (pending_multisig_transaction) = Multisig_pending_transaction.read();
        if (pending_multisig_transaction.transaction_hash == 0) {
            return (
                pending_multisig_transaction=pending_multisig_transaction,
                signer_ids_len=0,
                signer_ids=cast(0, felt*),
            );
        }
        let (num_ext_account_signers) = Signers_num_ext_account_signers.read();
        if (is_not_zero(num_ext_account_signers) == TRUE) {
            // Get signers, seed is not a valid signer
            let (num_multisig_signers) = Multisig_num_signers.read();
            let (signer_ids: felt*) = alloc();
            let (local signers_address_base) = Multisig_pending_transaction.addr();
            let signers_address_base = signers_address_base + 4;
            let (signer_ids_len) = pending_multisig_txn_signers_read(
                signers_base_address=signers_address_base,
                signers_address_offset=0,
                num_multisig_signers=num_multisig_signers,
                signer_ids_len=0,
                signer_ids=signer_ids,
                current_signer_id=0,
                assert_others=FALSE,
            );
            return (
                pending_multisig_transaction=pending_multisig_transaction,
                signer_ids_len=signer_ids_len,
                signer_ids=signer_ids,
            );
        } else {
            return (
                pending_multisig_transaction=pending_multisig_transaction,
                signer_ids_len=0, signer_ids=cast(0, felt*));
        }
    }

    func pending_multisig_transaction_signers_write{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } (
        signers_base_address: felt,
        signers_address_offset: felt,
        signer_ids_len: felt,
        signer_ids: felt*,
    ) -> () {
        if (signer_ids_len == 0) {
            return ();
        }
        let signer_0 = signer_ids[0];
        storage_write(address=signers_base_address + signers_address_offset, value=signer_ids[0]);
        pending_multisig_transaction_signers_write(
            signers_base_address, signers_address_offset + 1,
            signer_ids_len - 1,
            signer_ids + 1,
        );
        return ();
    }

    func pending_multisig_transaction_signers_wipe{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } (
        signers_base_address: felt,
        signers_address_offset: felt,
        signer_ids_len: felt,
    ) -> () {
        if (signer_ids_len == 0) {
            return ();
        }
        storage_write(address=signers_base_address + signers_address_offset, value=0);
        pending_multisig_transaction_signers_wipe(
            signers_base_address, signers_address_offset + 1,
            signer_ids_len - 1,
        );
        return ();
    }

    func pending_multisig_transaction_write{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(
        pending_multisig_txn: PendingMultisigTransaction,
        signers_base_address: felt,
        signer_ids_len: felt, signer_ids: felt*,
    ) -> () {
        Multisig_pending_transaction.write(pending_multisig_txn);
        pending_multisig_transaction_signers_write(
            signers_base_address,
            0,
            signer_ids_len, signer_ids,
        );

        return ();
    }

    func execute_pending_multisig_txn{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(
        pending_multisig_txn: PendingMultisigTransaction,
        signer_ids_len: felt, signer_ids: felt*,
        pending_calldata_len: felt, pending_calldata: felt*,
   ) -> (response_len: felt, response: felt*) {
        alloc_locals;
        // clear the pending txn and emit the event
        Multisig_pending_transaction.write(PendingMultisigTransaction(
            transaction_hash=0,
            expire_at_sec=0,
            expire_at_block_num=0,
            is_disable_multisig_transaction=0,
            signers=0,
        ));
        let (local signers_address_base) = Multisig_pending_transaction.addr();
        let signers_address_base = signers_address_base + 4;
        pending_multisig_transaction_signers_wipe(
            signers_address_base, 0, signer_ids_len,
        );

        // Convert `AccountCallArray` to 'Call'
        // we know pending_calldata is compatible with __execute__'s input
        let call_array_len = pending_calldata[0];
        let call_array = cast(pending_calldata + 1, AccountCallArray*);
        let (calls: Call*) = alloc();
        Account._from_call_array_to_call(
            call_array_len,
            call_array,
            pending_calldata + call_array_len *  AccountCallArray.SIZE + 2,
            calls
        );
        let calls_len = pending_calldata[0];

        // execute call
        let (response: felt*) = alloc();
        let (response_len) = Account._execute_list(calls_len, calls, response);

        return (response_len=response_len, response=response);
    }


    func pending_multisig_txn_signers_read{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(
        signers_base_address: felt,
        signers_address_offset: felt,
        num_multisig_signers: felt,
        signer_ids_len: felt,
        signer_ids: felt*,
        current_signer_id: felt,
        assert_others: felt,
    ) -> (signer_ids_len: felt) {
        alloc_locals;
        // Assuming seed signer is not a valid signer when calling this function
        // we can safely rely whether a slot is full iff slot != 0
        let (local read_signer_id) = storage_read(address=signers_base_address + signers_address_offset);

        if (assert_others == TRUE) {
            with_attr error_message("Multisig: current signer already signed multisig pending transaction") {
                assert is_not_zero(current_signer_id - read_signer_id) = 1;
            }
        }

        tempvar should_break = 1 - is_not_zero(read_signer_id) * is_not_zero(num_multisig_signers - signers_address_offset);
        if (should_break == TRUE) {
            return (signer_ids_len,);
        }
        assert [signer_ids] = read_signer_id;
        return pending_multisig_txn_signers_read(
            signers_base_address,
            signers_address_offset + 1,
            num_multisig_signers,
            signer_ids_len + 1,
            signer_ids + 1,
            current_signer_id,
            assert_others,
        );
    }


    func sign_pending_multisig_transaction{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(
        pending_calldata_len: felt, pending_calldata: felt*,
        pending_nonce: felt,
        pending_max_fee: felt,
        pending_transaction_version: felt
    ) -> (response_len: felt, response: felt*) {
        alloc_locals;

        let (pending_multisig_transaction) = Multisig_pending_transaction.read();
        let (num_multisig_signers) = Multisig_num_signers.read();
        let (local tx_info) = get_tx_info();

        let is_estfee = is_le_felt(TX_VERSION_1_EST_FEE, tx_info.version);
        // Let estimate fee pass for 2nd signer even when txn is still in RECEIVED state
        if (is_estfee == FALSE) {
            with_attr error_message("Multisig: no pending multisig transaction") {
                assert is_not_zero(pending_multisig_transaction.transaction_hash) = TRUE;
            }
        }

        let (multi_signers_len, multi_signers) = Signers.resolve_signers_from_sig(
            tx_info.signature_len, tx_info.signature);


        tempvar nonce_as_additional_data: felt* = new ( pending_nonce );
        let (self) = get_contract_address();
        with_attr error_message("Multisig: multisig invalid hash") {
            let hash_ptr = pedersen_ptr;
            with hash_ptr {
                let (computed_hash) = _compute_hash(
                    self, pending_calldata_len, pending_calldata,
                    pending_nonce, pending_max_fee,
                    pending_transaction_version, tx_info.chain_id,
                    nonce_as_additional_data
                );
            }
            let pedersen_ptr = hash_ptr;

            // Let estimate fee pass for 2nd signer even when txn is still in RECEIVED state
            if (is_estfee == FALSE) {
                assert computed_hash = pending_multisig_transaction.transaction_hash;
            }
        }

        // Send sign event for current signer
        let (local pendingTxnSignedEvtKeys: felt*) = alloc();
        assert [pendingTxnSignedEvtKeys]  = MultisigPendingTransactionSignedSelector;
        assert [pendingTxnSignedEvtKeys + 1] = computed_hash;
        let (local pendingTxnSignedEvtData: felt*) = alloc();
        assert [pendingTxnSignedEvtData] = multi_signers[0].index;
        emit_event(2, pendingTxnSignedEvtKeys, 1, pendingTxnSignedEvtData);

        // Save storage computation gas for the common consumer case of num_multisig_signers == 2
        if (num_multisig_signers == 2) {
            // Let estimate fee pass for 2nd signer even when txn is still in RECEIVED state
            if (is_estfee == FALSE) {
                with_attr error_message("Multisig: multisig signer can only sign once") {
                    assert multi_signers_len = 1;
                    assert is_not_zero(
                       multi_signers[0].index - pending_multisig_transaction.signers) = TRUE;
                }
            }
            tempvar signer_ids: felt* = new (multi_signers[0].index);
            return execute_pending_multisig_txn(pending_multisig_transaction,
                1, signer_ids,
                pending_calldata_len,
                pending_calldata,
            );
        }

        // From here on we assume account's seed signer is not a valid signer
        // this may change if we allow more than 2 signers in normal HWS + seed multisig mode
        let (local signers_address_base) = Multisig_pending_transaction.addr();
        let signers_address_base = signers_address_base + 4;
        let (signer_ids: felt*) = alloc();
        let (signer_ids_len) = pending_multisig_txn_signers_read(
            signers_base_address=signers_address_base,
            signers_address_offset=0,
            num_multisig_signers=num_multisig_signers,
            signer_ids_len=0,
            signer_ids=signer_ids,
            current_signer_id=multi_signers[0].index,
            assert_others=TRUE,
        );
        // Add current signer
        assert [signer_ids + signer_ids_len] = multi_signers[0].index;
        let signer_ids_len = signer_ids_len + 1;
        if (signer_ids_len == num_multisig_signers) {
            return execute_pending_multisig_txn(pending_multisig_transaction,
                signer_ids_len, signer_ids,
                pending_calldata_len, pending_calldata,
            );
        }

        pending_multisig_transaction_write(
            pending_multisig_transaction,
            signers_address_base,
            signer_ids_len, signer_ids,
        );

        return (response_len=0, response=cast(0, felt*));
    }

    func _compute_hash{
        syscall_ptr: felt*,
        hash_ptr: HashBuiltin*,
        range_check_ptr
    }(
        contract_address: felt,
        pending_calldata_len: felt, pending_calldata: felt*,
        pending_nonce: felt, pending_max_fee: felt,
        pending_transaction_version: felt,
        chain_id: felt, additional_data: felt*,
    ) -> (computed_hash: felt) {
        let (hash_state_ptr) = hash_init();
        let (hash_state_ptr) = hash_update_single(
            hash_state_ptr=hash_state_ptr, item=INVOKE_HASH_PREFIX);
        let (hash_state_ptr) = hash_update_single(
            hash_state_ptr=hash_state_ptr, item=pending_transaction_version
        );
        let (hash_state_ptr) = hash_update_single(
            hash_state_ptr=hash_state_ptr, item=contract_address
        );
        let (hash_state_ptr) = hash_update_single(
            hash_state_ptr=hash_state_ptr, item=0
        );
        let (hash_state_ptr) = hash_update_with_hashchain(
                hash_state_ptr=hash_state_ptr,
                data_ptr=pending_calldata,
                data_length=pending_calldata_len
        );
        let (hash_state_ptr) = hash_update_single(
            hash_state_ptr=hash_state_ptr, item=pending_max_fee
        );
        let (hash_state_ptr) = hash_update_single(
            hash_state_ptr=hash_state_ptr, item=chain_id
        );

        let (hash_state_ptr) = hash_update(
            hash_state_ptr=hash_state_ptr,
            data_ptr=additional_data,
            data_length=1
        );

        let (computed_hash) = hash_finalize(hash_state_ptr=hash_state_ptr);

        return (computed_hash=computed_hash);
    }

    func disable_multisig{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(num_ext_account_signers: felt) -> () {
        alloc_locals;
        with_attr error_message("Multisig: cannot disable multisig in external account signers mode") {
            assert num_ext_account_signers = 0;
        }
        // Discard any pending multisig txn
        Multisig_pending_transaction.write(PendingMultisigTransaction(
            transaction_hash=0,
            expire_at_sec=0,
            expire_at_block_num=0,
            is_disable_multisig_transaction=0,
            signers=0,
        ));
        let (local signers_address_base) = Multisig_pending_transaction.addr();
        let signers_address_base = signers_address_base + 4;
        let (num_multisig_signers) = Multisig_num_signers.read();
        pending_multisig_transaction_signers_wipe(
            signers_address_base, 0, num_multisig_signers,
        );

        // Remove multisig signer indication
        Multisig_num_signers.write(0);
        MultisigDisabled.emit();
        return ();
    }

    func disable_multisig_with_etd{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(account_etd: felt) -> () {

        // For now we limit this API to seed signer only as it has no functional
        // meaning with secp256r1
        let (tx_info) = get_tx_info();
        let (multi_signers_len, multi_signers) = Signers.resolve_signers_from_sig(
            tx_info.signature_len, tx_info.signature);
        with_attr error_message(
            "Multisig: disable_multisig_with_etd should be called with seed signer") {
            assert multi_signers_len = 1;
            assert multi_signers[0].signer.type = SIGNER_TYPE_STARK;
        }

        // We dont want to allow endless postponement of etd removals, once
        // there's an etd it should either finish or cancelled
        let (disable_multisig_req) = Multisig_deferred_disable_request.read();
        with_attr error_message(
            "Multisig: already have a pending disable multisig request") {
            assert disable_multisig_req.expire_at = 0;
        }

        let (block_timestamp) = get_block_timestamp();
        with_attr error_message("Multisig: etd not initialized") {
            assert_not_zero(account_etd);
        }
        let expire_at = block_timestamp + account_etd;
        let remove_req = DeferredMultisigDisableRequest(expire_at=expire_at);
        Multisig_deferred_disable_request.write(remove_req);
        MultisigDisableRequest.emit(remove_req);

        return ();
    }

    func get_deferred_disable_multisig_req{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }() -> (deferred_request: DeferredMultisigDisableRequest) {
        let (deferred_request) = Multisig_deferred_disable_request.read();
        return (deferred_request=deferred_request);
    }

    func cancel_deferred_disable_multisig_req{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }() -> () {
        let (deferred_request) = Multisig_deferred_disable_request.read();

        with_attr error_message("Multisig: no deferred disable multisig req") {
            assert_not_zero(deferred_request.expire_at);
        }

        Multisig_deferred_disable_request.write(
            DeferredMultisigDisableRequest(expire_at=0)
        );
        MultisigDisableRequestCancelled.emit(deferred_request);

        return ();
    }

    func is_non_deferred_selector_in_multisig{syscall_ptr: felt*}(
        to: felt,
        selector: felt
    ) -> (
        is_non_deferred: felt,
        is_sign_pending: felt,
        is_disable_multisig_with_etd: felt,
        is_remove_signer_with_etd: felt
    ) {
        let (self) = get_contract_address();
        if (to != self) {
            return (FALSE, FALSE, FALSE, FALSE);
        }

        tempvar is_sign_pending_selector = 1 - is_not_zero(
            selector - SIGN_PENDING_MULTISIG_TXN_SELECTOR);
        tempvar is_disable_multisig_with_etd_selector = 1 - is_not_zero(
            selector - DISABLE_MULTISIG_WITH_ETD_SELECTOR);
        tempvar is_remove_signer_with_etd_selector = 1 - is_not_zero(
            selector - REMOVE_SIGNER_WITH_ETD_SELECTOR);
        // Only one of the above will be 1 as we are comparing the same selector
        return  (
            is_non_deferred = (
                is_sign_pending_selector +
                is_disable_multisig_with_etd_selector +
                is_remove_signer_with_etd_selector
            ),
            is_sign_pending = is_sign_pending_selector,
            is_disable_multisig_with_etd = is_disable_multisig_with_etd_selector,
            is_remove_signer_with_etd = is_remove_signer_with_etd_selector,
        );

    }

    func discard_expired_multisig_pending_transaction{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,range_check_ptr,
    }(
        pending_multisig_txn: PendingMultisigTransaction,
        block_num: felt,
        block_timestamp: felt,
    ) -> (processed_pending_txn: PendingMultisigTransaction) {
        alloc_locals;
        if (pending_multisig_txn.transaction_hash == 0) {
            return (processed_pending_txn=pending_multisig_txn);
        }

        // only if both block and time elapsed then discard the pending txn
        let expiry_block_num_expired = is_le(
            pending_multisig_txn.expire_at_block_num, block_num);
        let expiry_sec_expired = is_le(
            pending_multisig_txn.expire_at_sec, block_timestamp);
        if (expiry_block_num_expired * expiry_sec_expired == TRUE) {
            let empty_pending_txn = PendingMultisigTransaction(
                transaction_hash=0,
                expire_at_sec=0,
                expire_at_block_num=0,
                is_disable_multisig_transaction=0,
                signers=0,
            );
            Multisig_pending_transaction.write(empty_pending_txn);
            let (local signers_address_base) = Multisig_pending_transaction.addr();
            let signers_address_base = signers_address_base + 4;
            let (num_multisig_signers) = Multisig_num_signers.read();
            pending_multisig_transaction_signers_wipe(
                signers_address_base, 0, num_multisig_signers,
            );
            return (processed_pending_txn=empty_pending_txn);
        }

        return (processed_pending_txn=pending_multisig_txn);

    }

    func apply_elapsed_etd_requests{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(block_timestamp: felt) -> () {
        let (disable_multisig_req) = Multisig_deferred_disable_request.read();
        let have_disable_multisig_etd = is_not_zero(disable_multisig_req.expire_at);
        let disable_multisig_etd_expired = is_le(
            disable_multisig_req.expire_at, block_timestamp);

        if (have_disable_multisig_etd * disable_multisig_etd_expired == TRUE) {
            disable_multisig(0);
            return();
        }

        return ();
    }

    func multisig_validate{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr,
        ecdsa_ptr: SignatureBuiltin*,
    }(
        call_array_len: felt, call_array: AccountCallArray*,
        calldata_len: felt, calldata: felt*,
        tx_info: TxInfo*, block_timestamp: felt, block_num: felt, is_estfee: felt,
        multi_signers_len: felt, multi_signers: IndexedSignerModel*,
        num_secp256r1_signers: felt, num_ext_account_signers: felt,
    ) -> (valid: felt, is_multisig_mode: felt) {
        alloc_locals;
        let (local self) = get_contract_address();
        let (local num_multisig_signers) = Multisig_num_signers.read();
        let is_multisig_mode = is_not_zero(num_multisig_signers);
        if (is_multisig_mode == FALSE) {
            return (valid=TRUE, is_multisig_mode=FALSE);
        }

        let num_account_signers = num_ext_account_signers + num_secp256r1_signers;
        if (num_account_signers == 0) {
            // This will happen when remove signer with etd was not bundled
            // with a disable multisig with etd, or all external account signers are removed,
            // so we handle it here.
            disable_multisig(0);
            return (valid=TRUE, is_multisig_mode=FALSE);
        }

        // From this point on, we are definitely in multisig mode
        let (pending_multisig_txn, local signer_ids_len, signer_ids) = get_pending_multisig_transaction();

        // In case more than one signature was sent atomically, enforce that at least m signers were sent.
        // resolve_signers_from_sig guarantees that there are no dups
        if (is_le(2, multi_signers_len) == TRUE) {
            with_attr error_message("Multisig: invalid amount of signers in signature") {
                assert is_le(num_multisig_signers, multi_signers_len) = TRUE;
            }

            return (valid=TRUE, is_multisig_mode=TRUE);
        } else {
            let range_check_ptr = range_check_ptr;
        }

        // In ext account signers mode, the first call is expected to be an assertion on the
        // expected max fee of the execution to avoid gas drainage by a malicious / compromised
        // last (executing) signer
        let (
            non_deferred_selector,
            is_sign_pending,
            is_disable_multisig_etd,
            _
        ) = is_non_deferred_selector_in_multisig(call_array[0].to, call_array[0].selector);

        tempvar enforce_max_fee_validation = (
            is_not_zero(num_ext_account_signers) * (1 - is_sign_pending));
        with_attr error_message("Multisig: max fee validation expected in first call") {
                assert (enforce_max_fee_validation *
                    ([call_array].selector - ASSERT_EXPECTED_MAX_FEE_SELECTOR)) = 0;
                assert (enforce_max_fee_validation *
                    ([call_array].to - self)) = 0;
        }


        // Limit intermediate signers to signing and updating of pending multisig txn (not exec)
        tempvar enforce_pre_final_signer_max_fee = (
            is_not_zero(num_ext_account_signers) * is_le(signer_ids_len, num_multisig_signers - 2)
        );
        with_attr error_message("Multisig: invalid max fee for intermediate signer") {
            assert (
                enforce_pre_final_signer_max_fee *
                is_le(MULTISIG_MOA_MAX_VALIDATE_FEE_FOR_PRE_EXEC_SIGNER, tx_info.max_fee)
            ) = 0;
        }
        let (pending_multisig_txn) = discard_expired_multisig_pending_transaction(
            pending_multisig_txn,
            block_num, block_timestamp,
        );

        let current_signer = multi_signers[0];

        tempvar is_stark_signer = 1 - is_not_zero(
            current_signer.signer.type - SIGNER_TYPE_STARK);
        let have_pending_txn = is_not_zero(pending_multisig_txn.transaction_hash);

        // Fail validate for invalid sign / etd invokes (REJECT instead of REVERT)
        with_attr error_message("Multisig: no pending transaction to sign") {
            // est fee or have pending txn or (not sign pending selector)
            assert (1 - is_estfee) * (1 - have_pending_txn) * (is_sign_pending) = FALSE;
        }

        with_attr error_message("Multisig: already have a pending disable multisig request") {
            let (dm_etd) = Multisig_deferred_disable_request.read();
            // (not dm etd selector) or (not have dm etd)
            assert is_disable_multisig_etd * is_not_zero(dm_etd.expire_at) = FALSE;
        }

        with_attr error_message("Multisig: disable_multisig_with_etd should be called with seed signer") {
            // (not dm etd selector) or stark signer
            assert is_disable_multisig_etd * (1 - is_stark_signer) = FALSE;
        }
        // Don't allow seed signer to override txns - only to approve them
        with_attr error_message("Multisig: seed signer cannot override pending transactions") {
            // (not seed signer) or (no pending txn) or non_deferred_selector
            assert is_stark_signer * have_pending_txn * (1 - non_deferred_selector) = FALSE;
        }
        // NOTE: The above limitation also protects against censorship when seed is stolen and
        // override pending multisig txns preventing HWS signer from recovering the account.
        // In this case, seed is only allowed to approve the txn or do ETD actions

        return (valid=TRUE, is_multisig_mode=TRUE);
    }
}
