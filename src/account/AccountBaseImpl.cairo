%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.math import assert_not_zero
from starkware.starknet.common.syscalls import get_contract_address, library_call, get_tx_info

from lib.openzeppelin.upgrades.library import Proxy
from src.account.library import Account
from src.utils.constants import INITIALIZER_SELECTOR


// The purpose of this contract is keeping Proxy CTOR params predictable thus
// making the account address predictable. This logic might move into the Proxy
// contract on the next breaking change (regenesis) as it does basically nothing
// and is "as static" as the Proxy contract.

@external
func initializer{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
}(public_key: felt) -> () {

    let (tx_info) = get_tx_info();
    let (actual_impl: felt, _: SignerModel) = Account.parse_initializer_signature_aux_data(
        tx_info.signature_len, tx_info.signature
    );

    with_attr error_message("Account Base: invalid actual implementation") {
        assert_not_zero(actual_impl);
    }

    tempvar calldata: felt* = new (public_key);
    library_call(
        class_hash=actual_impl,
        function_selector=INITIALIZER_SELECTOR,
        calldata_size=1,
        calldata=calldata,
    );

    Proxy._set_implementation(actual_impl);

    return ();
}