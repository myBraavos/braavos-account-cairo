%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.cairo_secp.bigint import uint256_to_bigint
from starkware.cairo.common.cairo_secp.ec import EcPoint
from starkware.cairo.common.default_dict import (
    default_dict_new,
    default_dict_finalize,
)
from starkware.cairo.common.dict import dict_read, dict_write
from starkware.cairo.common.dict_access import DictAccess
from starkware.cairo.common.math import (
    assert_le,
    assert_lt,
    assert_not_equal,
    assert_not_zero,
    split_felt,
    unsigned_div_rem,
)
from starkware.cairo.common.math_cmp import is_le, is_le_felt, is_not_zero
from starkware.cairo.common.memcpy import memcpy
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.uint256 import Uint256, uint256_check
from starkware.starknet.common.syscalls import (
    call_contract,
    get_block_timestamp,
    get_tx_info,
    TxInfo,
)

from lib.secp256r1.src.secp256r1.ec import verify_point
from lib.secp256r1.src.secp256r1.signature import verify_secp256r1_signature
from src.utils.constants import (
    ACCOUNT_MOA_DAILY_TXN_LIMIT,
    GET_PUBLIC_KEY_SELECTOR,
    IS_VALID_SIGNATURE_SELECTOR,
    NATIVE_STARK_SIG_LEN,
    STARK_SIG_LEN,
    SECP256R1_UINT256_SIG_LEN,
    STARK_PLUS_SECP256R1_SIG_LEN,
    REMOVE_SIGNER_WITH_ETD_SELECTOR,
    SIGNER_TYPE_EXTERNAL_ACCOUNT,
    SIGNER_TYPE_SECP256R1,
    SIGNER_TYPE_STARK,
    SIGNER_TYPE_UNUSED,
    TX_VERSION_1_EST_FEE
)

// Structs
struct SignerModel {
    signer_0: felt,
    signer_1: felt,
    signer_2: felt,
    signer_3: felt,
    type: felt,
    reserved_0: felt,
    reserved_1: felt,
}

struct IndexedSignerModel {
    index: felt,
    signer: SignerModel,
}

struct DeferredRemoveSignerRequest {
    expire_at: felt,
    signer_id: felt,
}

// Events
@event
func SignerRemoveRequest(request: DeferredRemoveSignerRequest) {
}

@event
func SignerAdded(signer_id: felt, signer: SignerModel) {
}

@event
func SignerRemoved(signer_id: felt) {
}

@event
func SignerRemoveRequestCancelled(request: DeferredRemoveSignerRequest) {
}

// Storage
@storage_var
func Account_public_key() -> (public_key: felt) {
}

@storage_var
func Account_signers(idx: felt) -> (signer: SignerModel) {
}

@storage_var
func Account_signers_max_index() -> (res: felt) {
}

@storage_var
func Account_signers_num_hw_signers() -> (res: felt) {
}

@storage_var
func Account_deferred_remove_signer() -> (res: DeferredRemoveSignerRequest) {
}

@storage_var
func Signers_num_ext_account_signers() -> (res: felt) {
}

@storage_var
func Signers_signer_daily_transaction_count(signer_id: felt, day_start_timestamp: felt) -> (
    num_of_daily_txns: felt) {
}

namespace Signers {

    func get_signers{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }() -> (signers_len: felt, signers: IndexedSignerModel*) {
        alloc_locals;
        let (max_id) = Account_signers_max_index.read();
        let (signers: IndexedSignerModel*) = alloc();
        let (num_signers) = _get_signers_inner(0, max_id, signers);
        return (signers_len=num_signers, signers=signers);
    }

    func _get_signers_inner{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(
        current_id: felt, max_id: felt, signers: IndexedSignerModel*
    ) -> (num_signers: felt) {
        let current_id_overflow = is_le(current_id, max_id);
        if (current_id_overflow == FALSE) {
            return (num_signers=0);
        }

        let (curr_signer) = Account_signers.read(current_id);
        if (curr_signer.type != SIGNER_TYPE_UNUSED) {
            assert [signers] = IndexedSignerModel(
                index=current_id,
                signer=SignerModel(
                    signer_0=curr_signer.signer_0,
                    signer_1=curr_signer.signer_1,
                    signer_2=curr_signer.signer_2,
                    signer_3=curr_signer.signer_3,
                    type=curr_signer.type,
                    reserved_0=curr_signer.reserved_0,
                    reserved_1=curr_signer.reserved_1
                    )
                );
            let (num_signers) = _get_signers_inner(
                current_id + 1, max_id, signers + IndexedSignerModel.SIZE
            );
            return (num_signers=num_signers + 1);
        } else {
            let (num_signers) = _get_signers_inner(current_id + 1, max_id, signers);
            return (num_signers=num_signers);
        }
    }

    func populate_ext_account_signer_addresses_dict{
        dict_ptr: DictAccess*,
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr,
    }(current_id: felt, max_id: felt) -> () {
        if (current_id == max_id + 1) {
            return ();
        }

        let (curr_signer) = Account_signers.read(current_id);
        if (curr_signer.type == SIGNER_TYPE_EXTERNAL_ACCOUNT) {
            dict_write(key=curr_signer.signer_0, new_value=1);
            return populate_ext_account_signer_addresses_dict(current_id + 1, max_id);
        } else {
            return populate_ext_account_signer_addresses_dict(current_id + 1, max_id);
        }

    }

    func get_signer{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(index: felt) -> (signer: SignerModel) {
        let (signer) = Account_signers.read(index);

        return (signer=signer);
    }

    func add_signer{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(signer: SignerModel) -> (signer_id: felt) {
        with_attr error_message("Signers: cannot add secp256r1 signer together with external account signers") {
            let (num_ext_signers) = Signers_num_ext_account_signers.read();
            assert num_ext_signers = 0;
        }

        with_attr error_message("Signers: can only add 1 secp256r1 signer") {
            assert signer.type = SIGNER_TYPE_SECP256R1;
            let (num_hw_signers) = Account_signers_num_hw_signers.read();
            assert num_hw_signers = 0;
            Account_signers_num_hw_signers.write(num_hw_signers + 1);
        }

        // Make sure we're adding a valid secp256r1 point
        with_attr error_message("Signers: invalid secp256r1 signer") {
            let x_uint256 = Uint256(low=signer.signer_0, high=signer.signer_1);
            uint256_check(x_uint256);
            let y_uint256 = Uint256(low=signer.signer_2, high=signer.signer_3);
            uint256_check(y_uint256);
            let (x_bigint3) = uint256_to_bigint(x_uint256);
            let (y_bigint3) = uint256_to_bigint(y_uint256);
            verify_point(EcPoint(x=x_bigint3, y=y_bigint3));
        }


        let (max_id) = Account_signers_max_index.read();
        let avail_id = max_id + 1;
        Account_signers.write(avail_id, signer);
        Account_signers_max_index.write(avail_id);

        SignerAdded.emit(avail_id, signer);
        return (signer_id=avail_id);
    }

    func add_external_account_signers {
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(
        ext_signer_addresses_len: felt,
        ext_signer_addresses: felt*,
    ) -> (num_ext_account_signers: felt) {
        alloc_locals;

        with_attr error_message("Signers: cannot add external account signers together with secp256r1 signer") {
            let (num_hw_signers) = Account_signers_num_hw_signers.read();
            assert num_hw_signers = 0;
        }

        with_attr error_message("Signers: must have at least 2 external account signers") {
            let (num_ext_signers) = Signers_num_ext_account_signers.read();
            let have_ext_signers = is_not_zero(num_ext_signers);
            // if have_ext_signers assert len > 0 else assert len > 1
            assert_lt(1 - have_ext_signers, ext_signer_addresses_len);
        }

        let (local max_id) = Account_signers_max_index.read();
        let (local ext_addresses_dict_start: DictAccess*) = default_dict_new(0);
        let ext_addresses_dict = ext_addresses_dict_start;
        populate_ext_account_signer_addresses_dict{dict_ptr=ext_addresses_dict}(0, max_id);
        _add_external_account_signers_inner{dict_ptr=ext_addresses_dict}(ext_signer_addresses_len, ext_signer_addresses, max_id);
        let (num_ext_signers_orig) = Signers_num_ext_account_signers.read();
        let num_ext_signers = num_ext_signers_orig + ext_signer_addresses_len;
        Signers_num_ext_account_signers.write(num_ext_signers);
        default_dict_finalize(
            ext_addresses_dict_start,
            ext_addresses_dict,
            0
        );

        Account_signers_max_index.write(max_id + ext_signer_addresses_len);

        return (num_ext_signers,);
    }

    func _add_external_account_signers_inner {
        dict_ptr: DictAccess*,
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(
        ext_signer_addresses_len: felt,
        ext_signer_addresses: felt*,
        curr_max_signer_id: felt,
    ) -> () {
        if (ext_signer_addresses_len == 0) {
            return ();
        }

        let (address_exists: felt) = dict_read(key=ext_signer_addresses[0]);

        with_attr error_message("Signers: external account signer address already exists") {
            assert address_exists = 0;
        }

        tempvar _empty_calldata = new ();
        with_attr error_message("Signers: error calling external signer's get_public_key") {
            let get_pub_key_res = call_contract(
                contract_address=ext_signer_addresses[0],
                function_selector=GET_PUBLIC_KEY_SELECTOR,
                calldata_size=0,
                calldata=_empty_calldata,
            );

            assert get_pub_key_res.retdata_size = 1;
        }

        let ext_account_signer = SignerModel(
            signer_0 = ext_signer_addresses[0],
            signer_1 = get_pub_key_res.retdata[0],
            signer_2 = 0,
            signer_3 = 0,
            type = SIGNER_TYPE_EXTERNAL_ACCOUNT,
            reserved_0 = 0,
            reserved_1 = 0,
        );

        let avail_id = curr_max_signer_id + 1;
        Account_signers.write(avail_id, ext_account_signer);
        dict_write(key=ext_signer_addresses[0], new_value=1);

        SignerAdded.emit(avail_id, ext_account_signer);
        return _add_external_account_signers_inner(ext_signer_addresses_len - 1,
            ext_signer_addresses + 1, curr_max_signer_id + 1);
    }


    func swap_signers{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(
        remove_index: felt,
        added_signer: SignerModel,
        in_multisig_mode: felt
) -> (signer_id: felt) {
        alloc_locals;

        let (local tx_info: TxInfo*) = get_tx_info();
        let (multi_signers_len, multi_signers) = resolve_signers_from_sig(
            tx_info.signature_len, tx_info.signature);

        // We only allow hw signer to swap unless we're in multisig then seed can also
        // initiate or approve swap_signers
        // If we arrived here in multisig then it's either
        // 1. A valid second signer from sign_pending_multisig flow
        // 2. A valid multi-signer 2nd sig
        // In both cases we should allow the swap to proceed
        with_attr error_message(
            "Signers: can only swap secp256r1 signers using a secp256r1 signer") {
            // DeMorgan on valid_signer OR multisig mode
            assert (1 - in_multisig_mode) * is_not_zero(
                multi_signers[0].signer.type - SIGNER_TYPE_SECP256R1) = FALSE;
        }

        with_attr error_message("Signers: cannot remove signer 0") {
            assert_not_equal(remove_index, 0);
        }
        let (removed_signer) = Account_signers.read(remove_index);
        with_attr error_message(
            "Signers: swap only supported for secp256r1 signer") {
            assert added_signer.type = SIGNER_TYPE_SECP256R1;
            assert removed_signer.type = SIGNER_TYPE_SECP256R1;
        }

        // At this point we verified
        // 1. a secp256r1 signer issued the request
        // 2. we're removing a secp256r1 signer
        // 3. we're adding a secp256r1 signer instead of the same type

        remove_signer(remove_index);

        let (added_signer_id) = add_signer(added_signer);

        return (signer_id=added_signer_id);
    }

    func _remove_external_account_signers_inner{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(
        remove_signer_ids_len: felt, remove_signer_ids: felt*,
    ) -> () {
        if (remove_signer_ids_len == 0) {
            return ();
        }

        let current_signer_id = remove_signer_ids[0];
        let (removed_signer) = Account_signers.read(remove_signer_ids[0]);
        with_attr error_message("Signers: tried removing invalid signer") {
            assert removed_signer.type = SIGNER_TYPE_EXTERNAL_ACCOUNT;
        }

        Account_signers.write(
            current_signer_id,
            SignerModel(
            signer_0=SIGNER_TYPE_UNUSED,
            signer_1=SIGNER_TYPE_UNUSED,
            signer_2=SIGNER_TYPE_UNUSED,
            signer_3=SIGNER_TYPE_UNUSED,
            type=SIGNER_TYPE_UNUSED,
            reserved_0=SIGNER_TYPE_UNUSED,
            reserved_1=SIGNER_TYPE_UNUSED
            ),
        );

        SignerRemoved.emit(current_signer_id);
        return _remove_external_account_signers_inner(remove_signer_ids_len - 1, remove_signer_ids + 1);
    }


    func remove_external_account_signers{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(
        remove_signer_ids_len: felt, remove_signer_ids: felt*,
    ) -> (res: felt) {
        alloc_locals;
        let (num_ext_account_signers) = Signers_num_ext_account_signers.read();
        local num_after_removal = num_ext_account_signers - remove_signer_ids_len;
        with_attr error_message("Signers: invalid amount of removed external account signers") {
            assert_le(2, num_after_removal);
        }

        _remove_external_account_signers_inner(remove_signer_ids_len, remove_signer_ids);
        Signers_num_ext_account_signers.write(num_after_removal);

        return (num_after_removal,);
    }

    func remove_signer{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(index: felt) -> () {
        // Make sure we remove a hw signer, this also implies that there is one
        let (removed_signer) = Account_signers.read(index);
        with_attr error_message("Signers: tried removing invalid signer") {
            assert removed_signer.type = SIGNER_TYPE_SECP256R1;
        }

        Account_signers.write(
            index,
            SignerModel(
            signer_0=SIGNER_TYPE_UNUSED,
            signer_1=SIGNER_TYPE_UNUSED,
            signer_2=SIGNER_TYPE_UNUSED,
            signer_3=SIGNER_TYPE_UNUSED,
            type=SIGNER_TYPE_UNUSED,
            reserved_0=SIGNER_TYPE_UNUSED,
            reserved_1=SIGNER_TYPE_UNUSED
            ),
        );

        Account_deferred_remove_signer.write(
            DeferredRemoveSignerRequest(
            expire_at=0,
            signer_id=0
            )
        );

        let (num_hw_signers) = Account_signers_num_hw_signers.read();
        // enforce only 1 additional signer - when support more need to guarantee
        // that non-hws cannot remove hws
        assert num_hw_signers = 1;
        Account_signers_num_hw_signers.write(num_hw_signers - 1);

        SignerRemoved.emit(index);
        return ();
    }

    func remove_signer_with_etd{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(index: felt, account_etd: felt) -> () {
        // Make sure we remove a hw signer, this also implies that there is one
        let (removed_signer) = Account_signers.read(index);
        with_attr error_message("Signers: tried removing invalid signer") {
            assert removed_signer.type = SIGNER_TYPE_SECP256R1;
        }

        let (block_timestamp) = get_block_timestamp();
        with_attr error_message("Signers: etd not initialized") {
            assert_not_zero(account_etd);
        }
        let expire_at = block_timestamp + account_etd;
        let remove_req = DeferredRemoveSignerRequest(expire_at=expire_at, signer_id=index);
        Account_deferred_remove_signer.write(remove_req);
        SignerRemoveRequest.emit(remove_req);
        return ();
    }

    func get_deferred_remove_signer_req{
        syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr
    }() -> (deferred_request: DeferredRemoveSignerRequest) {
        let (deferred_request) = Account_deferred_remove_signer.read();

        return (deferred_request=deferred_request);
    }

    func cancel_deferred_remove_signer_req{
        syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr
    }(removed_signer_id: felt) -> () {
        // remove_signer_id is for future compatibility where we can possibly have multiple hw signers
        let (deferred_request) = Account_deferred_remove_signer.read();

        with_attr error_message("Signers: invalid remove signer request to cancel") {
            assert_not_zero(deferred_request.expire_at);
            assert deferred_request.signer_id = removed_signer_id;
        }

        Account_deferred_remove_signer.write(
            DeferredRemoveSignerRequest(
            expire_at=0,
            signer_id=0
            )
        );
        SignerRemoveRequestCancelled.emit(deferred_request);

        return ();
    }

    func resolve_external_signers_from_sig_inner{
        dict_ptr: DictAccess*, // signer_ids_dict - use dict_ptr to re-use dict_read/write implicit
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(
        signature_len: felt,
        signature: felt*,
        signers_len: felt,
        signers: IndexedSignerModel*,
    ) -> (signers_len: felt) {
        if (signature_len == 0) {
            return (signers_len,);
        }
        let signer_id = signature[0];
        let (signer) = Account_signers.read(signer_id);
        with_attr error_message("Signers: expected external account signer") {
            assert signer.type = SIGNER_TYPE_EXTERNAL_ACCOUNT;
        }

        let (id_exists: felt) = dict_read(key=signer_id);
        with_attr error_message("Signers: duplicate external account signer id in signature") {
            assert id_exists = FALSE;
        }
        dict_write(key=signer_id, new_value=1);

        assert signers[0] = IndexedSignerModel(
            index=signature[0],
            signer=signer,
        );
        let signer_sig_length = signature[1];
        return resolve_external_signers_from_sig_inner(
            signature_len=signature_len - signer_sig_length - 2,
            signature=signature + signer_sig_length + 2,
            signers_len=signers_len + 1,
            signers=signers + IndexedSignerModel.SIZE,
        );

    }

    func resolve_signers_from_sig{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(
        signature_len: felt,
        signature: felt*
    ) -> (signers_len: felt, signers: IndexedSignerModel*) {
        alloc_locals;
        let res: IndexedSignerModel* = alloc();
        let (local num_ext_account_signers) = Signers_num_ext_account_signers.read();
        if (is_not_zero(num_ext_account_signers) == TRUE) {
            with_attr error_message("Signers: invalid external account signer signature") {
                // 1 signer idx + 2 felts (r,s) + (n > 0) felts for is_valid_sig call
                assert_le(4, signature_len);
                let (local signer_ids_dict_start: DictAccess*) = default_dict_new(0);
                let signer_ids_dict = signer_ids_dict_start;
                let (signers_len) = resolve_external_signers_from_sig_inner{
                    dict_ptr=signer_ids_dict}(
                    signature_len=signature_len - 3,
                    signature=signature + 3,
                    signers_len=0,
                    signers=res,
                );
                default_dict_finalize(signer_ids_dict_start, signer_ids_dict, 0);
                assert_le(1, signers_len);
            }
            return (signers_len=signers_len, signers=res);
        }

        // "native" stark signature
        if (signature_len == NATIVE_STARK_SIG_LEN) {
            let (seed_signer) = Account_signers.read(0);
            let indexed_signer = IndexedSignerModel(
                index=0,
                signer=seed_signer,
            );
            assert res[0] = indexed_signer;
            return (signers_len=1, signers=res);
        }

        let (local signer_1: SignerModel) = Account_signers.read(signature[0]);
        if (signature_len == STARK_SIG_LEN) {
            with_attr error_message("Signers: expected stark signer") {
                assert signer_1.type = SIGNER_TYPE_STARK;
            }
            assert res[0] = IndexedSignerModel(
                index=signature[0],
                signer=signer_1,
            );
            return (signers_len=1, signers=res);
        }

        if (signature_len == SECP256R1_UINT256_SIG_LEN) {
            with_attr error_message("Signers: expected secp256r1 signer") {
                assert signer_1.type = SIGNER_TYPE_SECP256R1;
            }
            assert res[0] = IndexedSignerModel(
                index=signature[0],
                signer=signer_1,
            );
            return (signers_len=1, signers=res);

        }

        if (signature_len == STARK_PLUS_SECP256R1_SIG_LEN) {
            if (signer_1.type == SIGNER_TYPE_STARK) {
                // Currently only supports seed + secp256r1 combination
                // (id_stark, r, s, id_secp256r1, r0, r1, s0, s1)
                assert res[0] = IndexedSignerModel(
                    index=signature[0],
                    signer=signer_1,
                );

                // stark sig is 3 felts (id, r, s) so offset to next sig is 3
                let signer_2_id = signature[3];
                let (signer_2) = Account_signers.read(signer_2_id);
                with_attr error_message("Signers: expected secp256r1 signer") {
                    assert signer_2.type = SIGNER_TYPE_SECP256R1;
                }
                assert res[1] = IndexedSignerModel(
                    index=signer_2_id,
                    signer=signer_2,
                );
                return (signers_len=2, signers=res);
            }
        }


        with_attr error_message("Signers: unexpected signature") {
            assert 1=0;
        }
        return (signers_len=0, signers=cast(0, IndexedSignerModel*));
    }

    func apply_elapsed_etd_requests{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(block_timestamp: felt) -> () {
        let (remove_signer_req) = Account_deferred_remove_signer.read();
        let have_remove_signer_etd = is_not_zero(remove_signer_req.expire_at);
        let remove_signer_etd_expired = is_le(remove_signer_req.expire_at, block_timestamp);

        if (have_remove_signer_etd * remove_signer_etd_expired == TRUE) {
            remove_signer(remove_signer_req.signer_id);
            return();
        }

        return ();
    }

    func verify_and_update_daily_txn_count{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr,
    }(
        have_ext_account_signers: felt,
        multi_signers_len: felt,
        signer_id: felt,
        block_timestamp: felt
    ) -> () {
        tempvar should_verify_and_update  = have_ext_account_signers * (
            1 - is_not_zero(multi_signers_len - 1));
        if (should_verify_and_update == FALSE) {
            return ();
        }

        let (day_since_epoch, _) = unsigned_div_rem(block_timestamp, 86400);
        let (signer_num_txns) = Signers_signer_daily_transaction_count.read(
                signer_id, day_since_epoch);
        with_attr error_message("Signers: daily transaction limit exceeded") {
            assert is_le(signer_num_txns, ACCOUNT_MOA_DAILY_TXN_LIMIT - 1) = TRUE;
        }

        Signers_signer_daily_transaction_count.write(
            signer_id,
            day_since_epoch,
            signer_num_txns + 1,
        );

        return ();
    }

    func signers_validate{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr,
        ecdsa_ptr: SignatureBuiltin*,
    }(
        call_array_len: felt, call_0_to: felt, call_0_sel: felt,
        calldata_len: felt, calldata: felt*,
        tx_info: TxInfo*, block_timestamp: felt, block_num: felt, is_estfee: felt,
        multi_signers_len: felt, multi_signers: IndexedSignerModel*,
        in_multisig_mode, num_secp256r1_signers: felt, num_ext_account_signers: felt,
    ) -> (valid: felt) {
        alloc_locals;
        local have_ext_account_signers = is_not_zero(num_ext_account_signers);
        // Authorize Signer
        _authorize_signer(
            tx_info.account_contract_address,
            tx_info.signature_len, tx_info.signature,
            call_array_len, call_0_to, call_0_sel,
            block_timestamp,
            in_multisig_mode,
            multi_signers_len, multi_signers,
            num_secp256r1_signers, have_ext_account_signers,
        );

        verify_and_update_daily_txn_count(
            have_ext_account_signers,
            multi_signers_len,
            multi_signers[0].index,
            block_timestamp
        );

        // For estimate fee txns we skip sig validation - client side should account for it
        if (is_estfee == TRUE) {
            return (valid = TRUE);
        }

        // Validate signature
        with_attr error_message("Signers: invalid signature") {
            let (is_valid) = is_valid_signature(
                tx_info.transaction_hash, tx_info.signature_len, tx_info.signature,
                multi_signers_len, multi_signers,
            );
            assert is_valid = TRUE;
        }

        return (valid=TRUE);
    }

    func _authorize_signer{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } (
        self: felt,
        signature_len: felt, signature: felt*,
        call_array_len: felt, call_0_to: felt, call_0_sel: felt,
        block_timestamp: felt,
        in_multisig_mode: felt,
        multi_signers_len: felt, multi_signers: IndexedSignerModel*,
        num_secp256r1_signers: felt, have_ext_account_signers: felt,
    ) -> () {
        alloc_locals;

        // Dont limit txns on: not(secp256r1) OR multisig
        // the if below is boolean equivalent via DeMorgan identity
        if (num_secp256r1_signers * (1 - in_multisig_mode) == FALSE) {
            return ();
        }

        with_attr error_message(
            "Signers: single-signer sig expected not in multisig mode") {
                assert multi_signers_len = 1;
        }

        if (multi_signers[0].signer.type == SIGNER_TYPE_SECP256R1) {
            // We either don't have a pending removal, or it wasn't expired yet
            // so we're good to go
            return ();
        }

        // else: At this point we have hws and not in multisig
        // Limit seed signer only to ETD signer removal
        with_attr error_message("Signers: invalid entry point for seed signing") {
            assert multi_signers[0].signer.type = SIGNER_TYPE_STARK;
            assert call_array_len = 1;
            assert call_0_to = self;
            assert call_0_sel = REMOVE_SIGNER_WITH_ETD_SELECTOR;
        }
        // 2. Fail if there's already a pending remove signer req
        with_attr error_message("Signers: already have a pending remove signer request") {
            let (remove_signer_req) = Account_deferred_remove_signer.read();
            assert remove_signer_req.expire_at = 0;
        }
        return ();
    }

    func _is_valid_stark_signature{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr,
        ecdsa_ptr: SignatureBuiltin*,
    }(
        public_key: felt,
        hash: felt,
        signature_len: felt, signature: felt*
    ) -> (is_valid: felt) {
        // This interface expects a signature pointer and length to make
        // no assumption about signature validation schemes.
        // But this implementation does, and it expects a (sig_r, sig_s) pair.
        let sig_r = signature[0];
        let sig_s = signature[1];

        verify_ecdsa_signature(
            message=hash, public_key=public_key, signature_r=sig_r, signature_s=sig_s
        );

        return (is_valid=TRUE);
    }

    func _is_valid_secp256r1_signature{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    }(
        signer: SignerModel,
        hash: felt,
        signature_len: felt, signature: felt*
    ) -> (is_valid: felt) {
        // x,y were verified in add_signer
        let (x) = uint256_to_bigint(Uint256(low=signer.signer_0, high=signer.signer_1));
        let (y) = uint256_to_bigint(Uint256(low=signer.signer_2, high=signer.signer_3));
        // validate r,s
        let r_uint256 = Uint256(low=signature[0], high=signature[1]);
        uint256_check(r_uint256);
        let s_uint256 = Uint256(low=signature[2], high=signature[3]);
        uint256_check(s_uint256);
        let (r_bigint3) = uint256_to_bigint(r_uint256);
        let (s_bigint3) = uint256_to_bigint(s_uint256);
        let (hash_high, hash_low) = split_felt(hash);
        let (hash_bigint3) = uint256_to_bigint(Uint256(low=hash_low, high=hash_high));
        verify_secp256r1_signature(hash_bigint3, r_bigint3, s_bigint3, EcPoint(x=x, y=y));
        return (is_valid=TRUE);
    }

    func is_valid_external_account_signers_signature{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr,
        ecdsa_ptr: SignatureBuiltin*,
    }(
        signers_len: felt,
        signers: IndexedSignerModel*,
        hash: felt,
        signature_len: felt, signature: felt*
    ) -> (is_valid: felt) {
        alloc_locals;
        if (signers_len == 0) {
            return (is_valid=TRUE);
        }
        // We have [ext_signer_id, sig_len, sig.., ext_signer_id, sig_len, sig..., and so on]
        // skip signer_id and signer extraction from sig we already got it in signers obj
        let signer_sig_len = signature[1];

        let (local calldata: felt*) = alloc();
        assert calldata[0] = hash;
        assert calldata[1] = signer_sig_len;
        let calldata_ptr = &calldata[2];
        memcpy(calldata_ptr, signature + 2, signer_sig_len);
        let res = call_contract(
            contract_address=signers[0].signer.signer_0,
            function_selector=IS_VALID_SIGNATURE_SELECTOR,
            calldata_size=signer_sig_len + 2,
            calldata=calldata,
        );

        assert res.retdata_size = 1;

        // Support both legacy Accounts and SRC6 compliant accounts
        tempvar valid = 1 - is_not_zero((res.retdata[0] - TRUE) * (res.retdata[0] - 'VALID'));
        if (valid == FALSE) {
            return (is_valid=FALSE);
        }

        return is_valid_external_account_signers_signature(
            signers_len=signers_len - 1,
            signers=signers + IndexedSignerModel.SIZE,
            hash=hash,
            signature_len=signature_len - 2 - signer_sig_len,
            signature=signature + 2 + signer_sig_len,
        );
    }

    func is_valid_signature_for_mode{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr,
        ecdsa_ptr: SignatureBuiltin*,
    } (
        hash: felt,
        signature_len: felt, signature: felt*,
        multisig_num_signers: felt,
        have_secp256r1_signer: felt,
        have_ext_account_signer: felt,
    ) -> (is_valid: felt) {
        let (multi_signers_len , multi_signers) = resolve_signers_from_sig(
                signature_len, signature);
        tempvar is_stark_sig = 1 - is_not_zero((signature_len - NATIVE_STARK_SIG_LEN)*(signature_len - STARK_SIG_LEN));
        tempvar is_secp256r1_sig = 1 - is_not_zero(signature_len - SECP256R1_UINT256_SIG_LEN);
        tempvar is_multisig_sig = is_le(2, multi_signers_len);
        tempvar in_multisig_mode = is_not_zero(multisig_num_signers);

        // only 1 of the _sig params will be assigned 1 and will choose the correct
        // condition below
        if ((1 - have_ext_account_signer) * (
            (is_stark_sig * (1 - have_secp256r1_signer) +
            is_secp256r1_sig * (1 - in_multisig_mode) +
            is_multisig_sig * in_multisig_mode)) == TRUE) {
            return is_valid_signature(
                hash,
                signature_len, signature,
                multi_signers_len, multi_signers,
            );
        }

        if (have_ext_account_signer * is_le(multisig_num_signers, multi_signers_len) == TRUE) {
            return is_valid_external_account_signers_signature(
                multi_signers_len, multi_signers,
                hash,
                signature_len - 3, signature + 3,
            );
        }


        return (is_valid = FALSE);
    }

    func is_valid_signature{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr,
        ecdsa_ptr: SignatureBuiltin*,
    }(
        hash: felt,
        signature_len: felt, signature: felt*,
        multi_signers_len: felt, multi_signers: IndexedSignerModel*,
    ) -> (is_valid: felt) {
        alloc_locals;

        // Single sig consumer-multisig flow - stark + secp256r1
        if (multi_signers_len == 2 and multi_signers[0].signer.type == SIGNER_TYPE_STARK) {
            let (valid) = Signers._is_valid_stark_signature(
                multi_signers[0].signer.signer_0,
                hash,
                2, signature + 1
            );

            with_attr error_message("Multisig: invalid stark signer sig") {
                assert valid=TRUE;
            }

            let (valid) = Signers._is_valid_secp256r1_signature(
                multi_signers[1].signer,
                hash,
                4, signature + 4
            );

            with_attr error_message("Multisig: invalid secp256r1 signer sig") {
                assert valid=TRUE;
            }

            return (is_valid=TRUE);

        }

        if (multi_signers_len == 1 and multi_signers[0].signer.type == SIGNER_TYPE_STARK) {
            let sig_offset = is_not_zero(signature_len - NATIVE_STARK_SIG_LEN);  // Support native stark sig
            _is_valid_stark_signature(
                multi_signers[0].signer.signer_0,
                hash,
                signature_len - sig_offset, signature + sig_offset,
            );
            return (is_valid=TRUE);
        }

        if (multi_signers_len == 1 and multi_signers[0].signer.type == SIGNER_TYPE_SECP256R1) {
            _is_valid_secp256r1_signature(
                multi_signers[0].signer,
                hash,
                signature_len - 1, signature + 1
            );
            return (is_valid=TRUE);
        }

        if (multi_signers[0].signer.type == SIGNER_TYPE_EXTERNAL_ACCOUNT) {
            let (ext_signers_sig_preamble_signer) = Account_signers.read(signature[0]);
            with_attr error_message("Signers: invalid signature") {
                assert ext_signers_sig_preamble_signer.type = SIGNER_TYPE_EXTERNAL_ACCOUNT;
            }
            // Since we can't call is_valid_signature from validate
            // we validate stark sig of external account to prevent DOS
            // calling is_valid_signature on the external signer/s is done
            // in multisig_execute via is_valid_external_account_signers_signature
            _is_valid_stark_signature(
                ext_signers_sig_preamble_signer.signer_1,
                hash,
                signature_len - 1, signature + 1,
            );

            return (is_valid=TRUE);
        }



        // Unsupported signer type!
        with_attr error_message("Signers: unsupported signer type") {
            assert_not_zero(0);
        }

        return (is_valid=FALSE);
    }

    func signers_execute{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr,
        ecdsa_ptr: SignatureBuiltin*,
    }(tx_info: TxInfo*) -> (res: felt) {
        let (num_ext_account_signers) = Signers_num_ext_account_signers.read();

        if (num_ext_account_signers == 0) {
            return (TRUE,);
        }

        // Skip validation in estimate fee
        if (is_le_felt(TX_VERSION_1_EST_FEE, tx_info.version) == TRUE) {
            return (TRUE,);
        }

        let (multi_signers_len, multi_signers) = resolve_signers_from_sig(
            tx_info.signature_len, tx_info.signature
        );
        with_attr error_message("Signers: invalid external account signers signature") {
            assert_le(1, multi_signers_len);
            let (is_valid) = is_valid_external_account_signers_signature(
                signers_len=multi_signers_len,
                signers=multi_signers,
                hash=tx_info.transaction_hash,
                signature_len=tx_info.signature_len - 3, // remove ext signer seed preamble
                signature=tx_info.signature + 3,
            );
            assert is_valid = TRUE;
        }

        return (TRUE,);
    }

}
