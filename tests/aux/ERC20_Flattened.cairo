// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts for Cairo v0.2.0 (token/erc20/ERC20.cairo)

// Adopted from OZ ERC20 0.2.0 flattened into a single file

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.uint256 import (
    Uint256,
    uint256_check,
    uint256_add,
    uint256_sub,
    uint256_mul,
    uint256_unsigned_div_rem,
    uint256_le,
    uint256_lt,
    uint256_eq,
    uint256_not,
)
from starkware.starknet.common.syscalls import get_caller_address
from starkware.cairo.common.math import assert_not_zero, assert_lt

const UINT8_MAX = 256;

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    name: felt, symbol: felt, decimals: felt, initial_supply: Uint256, recipient: felt
) {
    ERC20.initializer(name, symbol, decimals);
    ERC20._mint(recipient, initial_supply);
    return ();
}

//
// Getters
//

@view
func name{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (name: felt) {
    let (name) = ERC20.name();
    return (name,);
}

@view
func symbol{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (symbol: felt) {
    let (symbol) = ERC20.symbol();
    return (symbol,);
}

@view
func totalSupply{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    totalSupply: Uint256
) {
    let (totalSupply: Uint256) = ERC20.total_supply();
    return (totalSupply,);
}

@view
func decimals{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    decimals: felt
) {
    let (decimals) = ERC20.decimals();
    return (decimals,);
}

@view
func balanceOf{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(account: felt) -> (
    balance: Uint256
) {
    let (balance: Uint256) = ERC20.balance_of(account);
    return (balance,);
}

@view
func allowance{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    owner: felt, spender: felt
) -> (remaining: Uint256) {
    let (remaining: Uint256) = ERC20.allowance(owner, spender);
    return (remaining,);
}

//
// Externals
//

@external
func transfer{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    recipient: felt, amount: Uint256
) -> (success: felt) {
    ERC20.transfer(recipient, amount);
    return (TRUE,);
}

@external
func transferFrom{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    sender: felt, recipient: felt, amount: Uint256
) -> (success: felt) {
    ERC20.transfer_from(sender, recipient, amount);
    return (TRUE,);
}

@external
func approve{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    spender: felt, amount: Uint256
) -> (success: felt) {
    ERC20.approve(spender, amount);
    return (TRUE,);
}

@external
func increaseAllowance{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    spender: felt, added_value: Uint256
) -> (success: felt) {
    ERC20.increase_allowance(spender, added_value);
    return (TRUE,);
}

namespace SafeUint256 {
    // Adds two integers.
    // Reverts if the sum overflows.
    func add{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        a: Uint256, b: Uint256
    ) -> (c: Uint256) {
        uint256_check(a);
        uint256_check(b);
        let (c: Uint256, is_overflow) = uint256_add(a, b);
        with_attr error_message("SafeUint256: addition overflow") {
            assert is_overflow = FALSE;
        }
        return (c,);
    }

    // Subtracts two integers.
    // Reverts if minuend (`b`) is greater than subtrahend (`a`).
    func sub_le{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        a: Uint256, b: Uint256
    ) -> (c: Uint256) {
        alloc_locals;
        uint256_check(a);
        uint256_check(b);
        let (is_le) = uint256_le(b, a);
        with_attr error_message("SafeUint256: subtraction overflow") {
            assert is_le = TRUE;
        }
        let (c: Uint256) = uint256_sub(a, b);
        return (c,);
    }

    // Subtracts two integers.
    // Reverts if minuend (`b`) is greater than or equal to subtrahend (`a`).
    func sub_lt{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        a: Uint256, b: Uint256
    ) -> (c: Uint256) {
        alloc_locals;
        uint256_check(a);
        uint256_check(b);

        let (is_lt) = uint256_lt(b, a);
        with_attr error_message("SafeUint256: subtraction overflow or the difference equals zero") {
            assert is_lt = TRUE;
        }
        let (c: Uint256) = uint256_sub(a, b);
        return (c,);
    }

    // Multiplies two integers.
    // Reverts if product is greater than 2^256.
    func mul{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        a: Uint256, b: Uint256
    ) -> (c: Uint256) {
        alloc_locals;
        uint256_check(a);
        uint256_check(b);
        let (a_zero) = uint256_eq(a, Uint256(0, 0));
        if (a_zero == TRUE) {
            return (a,);
        }

        let (b_zero) = uint256_eq(b, Uint256(0, 0));
        if (b_zero == TRUE) {
            return (b,);
        }

        let (c: Uint256, overflow: Uint256) = uint256_mul(a, b);
        with_attr error_message("SafeUint256: multiplication overflow") {
            assert overflow = Uint256(0, 0);
        }
        return (c,);
    }

    // Integer division of two numbers. Returns uint256 quotient and remainder.
    // Reverts if divisor is zero as per OpenZeppelin's Solidity implementation.
    // Cairo's `uint256_unsigned_div_rem` already checks:
    //    remainder < divisor
    //    quotient * divisor + remainder == dividend
    func div_rem{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        a: Uint256, b: Uint256
    ) -> (c: Uint256, rem: Uint256) {
        alloc_locals;
        uint256_check(a);
        uint256_check(b);

        let (is_zero) = uint256_eq(b, Uint256(0, 0));
        with_attr error_message("SafeUint256: divisor cannot be zero") {
            assert is_zero = FALSE;
        }

        let (c: Uint256, rem: Uint256) = uint256_unsigned_div_rem(a, b);
        return (c, rem);
    }
}

//
// Events
//

@event
func Transfer(from_: felt, to: felt, value: Uint256) {
}

@event
func Approval(owner: felt, spender: felt, value: Uint256) {
}

//
// Storage
//

@storage_var
func ERC20_name() -> (name: felt) {
}

@storage_var
func ERC20_symbol() -> (symbol: felt) {
}

@storage_var
func ERC20_decimals() -> (decimals: felt) {
}

@storage_var
func ERC20_total_supply() -> (total_supply: Uint256) {
}

@storage_var
func ERC20_balances(account: felt) -> (balance: Uint256) {
}

@storage_var
func ERC20_allowances(owner: felt, spender: felt) -> (allowance: Uint256) {
}

namespace ERC20 {
    //
    // Initializer
    //

    func initializer{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        name: felt, symbol: felt, decimals: felt
    ) {
        ERC20_name.write(name);
        ERC20_symbol.write(symbol);
        with_attr error_message("ERC20: decimals exceed 2^8") {
            assert_lt(decimals, UINT8_MAX);
        }
        ERC20_decimals.write(decimals);
        return ();
    }

    //
    // Public functions
    //

    func name{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (name: felt) {
        let (name) = ERC20_name.read();
        return (name,);
    }

    func symbol{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
        symbol: felt
    ) {
        let (symbol) = ERC20_symbol.read();
        return (symbol,);
    }

    func total_supply{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
        total_supply: Uint256
    ) {
        let (total_supply: Uint256) = ERC20_total_supply.read();
        return (total_supply,);
    }

    func decimals{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
        decimals: felt
    ) {
        let (decimals) = ERC20_decimals.read();
        return (decimals,);
    }

    func balance_of{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        account: felt
    ) -> (balance: Uint256) {
        let (balance: Uint256) = ERC20_balances.read(account);
        return (balance,);
    }

    func allowance{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        owner: felt, spender: felt
    ) -> (remaining: Uint256) {
        let (remaining: Uint256) = ERC20_allowances.read(owner, spender);
        return (remaining,);
    }

    func transfer{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        recipient: felt, amount: Uint256
    ) {
        let (sender) = get_caller_address();
        _transfer(sender, recipient, amount);
        return ();
    }

    func transfer_from{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        sender: felt, recipient: felt, amount: Uint256
    ) -> () {
        let (caller) = get_caller_address();
        // subtract allowance
        _spend_allowance(sender, caller, amount);
        // execute transfer
        _transfer(sender, recipient, amount);
        return ();
    }

    func approve{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        spender: felt, amount: Uint256
    ) {
        with_attr error_message("ERC20: amount is not a valid Uint256") {
            uint256_check(amount);
        }

        let (caller) = get_caller_address();
        _approve(caller, spender, amount);
        return ();
    }

    func increase_allowance{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        spender: felt, added_value: Uint256
    ) -> () {
        with_attr error("ERC20: added_value is not a valid Uint256") {
            uint256_check(added_value);
        }

        let (caller) = get_caller_address();
        let (current_allowance: Uint256) = ERC20_allowances.read(caller, spender);

        // add allowance
        with_attr error_message("ERC20: allowance overflow") {
            let (new_allowance: Uint256) = SafeUint256.add(current_allowance, added_value);
        }

        _approve(caller, spender, new_allowance);
        return ();
    }

    func decrease_allowance{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        spender: felt, subtracted_value: Uint256
    ) -> () {
        alloc_locals;
        with_attr error_message("ERC20: subtracted_value is not a valid Uint256") {
            uint256_check(subtracted_value);
        }

        let (caller) = get_caller_address();
        let (current_allowance: Uint256) = ERC20_allowances.read(owner=caller, spender=spender);

        with_attr error_message("ERC20: allowance below zero") {
            let (new_allowance: Uint256) = SafeUint256.sub_le(current_allowance, subtracted_value);
        }

        _approve(caller, spender, new_allowance);
        return ();
    }

    //
    // Internal
    //

    func _mint{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        recipient: felt, amount: Uint256
    ) {
        with_attr error_message("ERC20: amount is not a valid Uint256") {
            uint256_check(amount);
        }

        with_attr error_message("ERC20: cannot mint to the zero address") {
            assert_not_zero(recipient);
        }

        let (supply: Uint256) = ERC20_total_supply.read();
        with_attr error_message("ERC20: mint overflow") {
            let (new_supply: Uint256) = SafeUint256.add(supply, amount);
        }
        ERC20_total_supply.write(new_supply);

        let (balance: Uint256) = ERC20_balances.read(account=recipient);
        // overflow is not possible because sum is guaranteed to be less than total supply
        // which we check for overflow below
        let (new_balance: Uint256) = SafeUint256.add(balance, amount);
        ERC20_balances.write(recipient, new_balance);

        Transfer.emit(0, recipient, amount);
        return ();
    }

    func _burn{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        account: felt, amount: Uint256
    ) {
        with_attr error_message("ERC20: amount is not a valid Uint256") {
            uint256_check(amount);
        }

        with_attr error_message("ERC20: cannot burn from the zero address") {
            assert_not_zero(account);
        }

        let (balance: Uint256) = ERC20_balances.read(account);
        with_attr error_message("ERC20: burn amount exceeds balance") {
            let (new_balance: Uint256) = SafeUint256.sub_le(balance, amount);
        }

        ERC20_balances.write(account, new_balance);

        let (supply: Uint256) = ERC20_total_supply.read();
        let (new_supply: Uint256) = SafeUint256.sub_le(supply, amount);
        ERC20_total_supply.write(new_supply);
        Transfer.emit(account, 0, amount);
        return ();
    }

    func _transfer{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        sender: felt, recipient: felt, amount: Uint256
    ) {
        with_attr error_message("ERC20: amount is not a valid Uint256") {
            uint256_check(amount);  // almost surely not needed, might remove after confirmation
        }

        with_attr error_message("ERC20: cannot transfer from the zero address") {
            assert_not_zero(sender);
        }

        with_attr error_message("ERC20: cannot transfer to the zero address") {
            assert_not_zero(recipient);
        }

        let (sender_balance: Uint256) = ERC20_balances.read(account=sender);
        with_attr error_message("ERC20: transfer amount exceeds balance") {
            let (new_sender_balance: Uint256) = SafeUint256.sub_le(sender_balance, amount);
        }

        ERC20_balances.write(sender, new_sender_balance);

        // add to recipient
        let (recipient_balance: Uint256) = ERC20_balances.read(account=recipient);
        // overflow is not possible because sum is guaranteed by mint to be less than total supply
        let (new_recipient_balance: Uint256) = SafeUint256.add(recipient_balance, amount);
        ERC20_balances.write(recipient, new_recipient_balance);
        Transfer.emit(sender, recipient, amount);
        return ();
    }

    func _approve{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        owner: felt, spender: felt, amount: Uint256
    ) {
        with_attr error_message("ERC20: amount is not a valid Uint256") {
            uint256_check(amount);
        }

        with_attr error_message("ERC20: cannot approve from the zero address") {
            assert_not_zero(owner);
        }

        with_attr error_message("ERC20: cannot approve to the zero address") {
            assert_not_zero(spender);
        }

        ERC20_allowances.write(owner, spender, amount);
        Approval.emit(owner, spender, amount);
        return ();
    }

    func _spend_allowance{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        owner: felt, spender: felt, amount: Uint256
    ) {
        alloc_locals;
        with_attr error_message("ERC20: amount is not a valid Uint256") {
            uint256_check(amount);  // almost surely not needed, might remove after confirmation
        }

        let (current_allowance: Uint256) = ERC20_allowances.read(owner, spender);
        let (infinite: Uint256) = uint256_not(Uint256(0, 0));
        let (is_infinite: felt) = uint256_eq(current_allowance, infinite);

        if (is_infinite == FALSE) {
            with_attr error_message("ERC20: insufficient allowance") {
                let (new_allowance: Uint256) = SafeUint256.sub_le(current_allowance, amount);
            }

            _approve(owner, spender, new_allowance);
            return ();
        }
        return ();
    }
}

@external
func decreaseAllowance{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    spender: felt, subtracted_value: Uint256
) -> (success: felt) {
    ERC20.decrease_allowance(spender, subtracted_value);
    return (TRUE,);
}
