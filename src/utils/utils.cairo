use array::{ArrayTrait, SpanTrait};
use core::num::traits::WideMul;
use integer::{u256_as_non_zero, u512, u512_safe_div_rem_by_u256};
use option::OptionTrait;
use serde::Serde;
use starknet::SyscallResultTrait;
use starknet::account::Call;
use starknet::info::v2::{ResourceBounds, TxInfo};
use starknet::syscalls::call_contract_syscall;
use traits::{Into, TryInto};


mod Consts {
    const L1_GAS_RESOURCE: felt252 = 'L1_GAS';
    const L2_GAS_RESOURCE: felt252 = 'L2_GAS';
    const L1_DATA_GAS_RESOURCE: felt252 = 'L1_DATA';
}

trait IntoOrPanic<S, T> {
    fn into_or_panic(self: S) -> T;
}

impl SpanFelt252IntoU256 of IntoOrPanic<Span<felt252>, u256> {
    fn into_or_panic(self: Span<felt252>) -> u256 {
        assert(self.len() == 8, 'INVALID_FELT252s_U256_CONV_LEN');
        u256 {
            high: ((*self.at(0)).try_into().unwrap() * 0x1000000000000000000000000_u128
                + (*self.at(1)).try_into().unwrap() * 0x10000000000000000_u128
                + (*self.at(2)).try_into().unwrap() * 0x100000000_u128
                + (*self.at(3)).try_into().unwrap()),
            low: ((*self.at(4)).try_into().unwrap() * 0x1000000000000000000000000_u128
                + (*self.at(5)).try_into().unwrap() * 0x10000000000000000_u128
                + (*self.at(6)).try_into().unwrap() * 0x100000000_u128
                + (*self.at(7)).try_into().unwrap()),
        }
    }
}

impl SpanFelt252IntoArray<
    T, +TryInto<felt252, T>, +Drop<T>,
> of IntoOrPanic<Span<felt252>, Array<T>> {
    fn into_or_panic(self: Span<felt252>) -> Array<T> {
        let mut arr: Array<T> = array![];
        let mut i = 0;
        loop {
            if i == self.len() {
                break;
            }

            arr.append((*self.at(i)).try_into().unwrap());
            i += 1;
        }

        arr
    }
}

fn base64_char_to_uint6(base64_char: u8) -> u8 {
    let mut uint6 = 0;
    if base64_char >= 'A' && base64_char <= 'Z' {
        uint6 = base64_char - 'A';
    } else if base64_char >= 'a' && base64_char <= 'z' {
        uint6 = (base64_char - 'a') + 26;
    } else if (base64_char >= '0') && (base64_char <= '9') {
        uint6 = (base64_char - '0') + 52;
    } else if (base64_char == '-') {
        uint6 = 62;
    } else if base64_char == '_' {
        uint6 = 63;
    } else {
        panic_with_felt252('INVALID_BASE64_CHAR');
    }
    uint6
}


fn reconstruct_hash_from_challenge(
    ref challenge_u32: Span<felt252>, offset: u32, challenge_len: u32, padding: u8,
) -> felt252 {
    assert(padding != 0, 'INVALID_FELT252_BASE64');
    let mut curr_u32: u32 = (*challenge_u32.pop_back().unwrap()).try_into().unwrap();
    let rev_offset = 3 - (challenge_len + offset - 1) % 4;
    let mut curr_shift = 1;
    let mut i = 0;
    loop {
        if (i == rev_offset) {
            break;
        }
        curr_shift *= 0x100;
        i += 1;
    }

    let val: u8 = ((curr_u32 / curr_shift) & 0xFF).try_into().unwrap();
    let mut first_uint6 = base64_char_to_uint6(val) / padding;
    let mut amount: felt252 = first_uint6.into();
    let mut multiplier: felt252 = (64 / padding).into();
    i = 1;
    loop {
        if curr_shift == 0x1000000 {
            curr_shift = 1;
            curr_u32 = (*challenge_u32.pop_back().unwrap()).try_into().unwrap();
        } else {
            curr_shift *= 0x100;
        }

        let val: u8 = ((curr_u32 / curr_shift) & 0xFF).try_into().unwrap();
        let limb = base64_char_to_uint6(val).into() * multiplier;
        i += 1;
        if i == challenge_len {
            break (limb + amount);
        }
        amount += limb;
        multiplier *= 64;
    }
}

fn mulDiv(a: u256, b: u256, c: u256) -> u256 {
    let x: u512 = WideMul::wide_mul(a, b);
    let (res, _) = u512_safe_div_rem_by_u256(x, u256_as_non_zero(c));
    assert(res.limb2 + res.limb3 == 0, 'OVF');
    let x: u256 = u256 { low: res.limb0, high: res.limb1 };
    return x;
}

fn concat_u32_with_padding(
    first_span: Span<felt252>, ref second_span: Span<felt252>, padding: u32,
) -> (Array<felt252>, u32) {
    let mut concat_data: Array<felt252> = array![];
    let mut i = 0;
    let first_len = first_span.len() - 1;
    loop {
        if i == first_len {
            break;
        }
        concat_data.append(*first_span.at(i));
        i += 1;
    }
    let mut prev: u32 = (*first_span.at(first_len)).try_into().unwrap();
    assert(padding < 4, 'INVALID_PADDING');
    let (denom, mul, rem) = if (padding == 1) {
        (0x1000000, 0x100, 0xFFFFFF)
    } else if (padding == 2) {
        (0x10000, 0x10000, 0xFFFF)
    } else if (padding == 3) {
        (0x100, 0x1000000, 0xFF)
    } else {
        (0x0, 0x1, 0xFFFFFFFF)
    };
    loop {
        match second_span.pop_front() {
            Option::Some(elem) => {
                let val: u32 = (*elem).try_into().unwrap();
                if (denom != 0) {
                    prev += (val / denom);
                }
                concat_data.append(prev.into());
                prev = (val & rem) * mul;
            },
            Option::None => { break; },
        };
    }
    (concat_data, prev)
}

fn u32_shr_div_for_pos(pos_in_u32: u32) -> u32 {
    if pos_in_u32 == 0 {
        0x1000000_u32
    } else if pos_in_u32 == 1 {
        0x10000_u32
    } else if pos_in_u32 == 2 {
        0x100_u32
    } else if pos_in_u32 == 3 {
        1_u32
    } else {
        panic_with_felt252('INVALID_POS_IN_U32');
        0_u32
    }
}

/// Helper function that fetches the fee and tx version from exec info. Fee calculation
/// depends on tx version.
/// for v1 we take the max_info value
/// for v3 we return (L1_max_amount * L1_max_price_per_unit) +
/// L1_data_max_amount * L1_data_max_price_per_unit +
/// L2_max_amount * (L2_max_price_per_unit + tip)
/// for pre 0.13.4 starknet version l1 data gas resource bound does not exist
/// and will be set to 0
fn extract_fee_from_tx(tx_info: @TxInfo, version: u256) -> u256 {
    if version.low == 1 {
        return (*tx_info.max_fee).into();
    } else if version.low == 3 {
        assert((*tx_info.resource_bounds).len() >= 2, 'INVALID_TX');
        let mut l1_gas_overall: u256 = 0;
        let mut l1_data_gas_overall: u256 = 0;
        let mut l2_gas_overall: u256 = 0;
        for resource_bound in *tx_info.resource_bounds {
            if *resource_bound.resource == Consts::L1_GAS_RESOURCE {
                let max_amount: u256 = (*resource_bound.max_amount).into();
                let max_price_per_unit: u256 = (*resource_bound.max_price_per_unit).into();
                l1_gas_overall = max_amount * max_price_per_unit;
            } else if *resource_bound.resource == Consts::L1_DATA_GAS_RESOURCE {
                let max_amount: u256 = (*resource_bound.max_amount).into();
                let max_price_per_unit: u256 = (*resource_bound.max_price_per_unit).into();
                l1_data_gas_overall = max_amount * max_price_per_unit;
            } else if *resource_bound.resource == Consts::L2_GAS_RESOURCE {
                let max_amount: u256 = (*resource_bound.max_amount).into();
                let max_price_per_unit: u256 = (*resource_bound.max_price_per_unit).into();
                let tip: u256 = (*tx_info.tip).into();
                l2_gas_overall = max_amount * (max_price_per_unit + tip);
            }
        }
        return l1_gas_overall + l1_data_gas_overall + l2_gas_overall;
    } else {
        panic_with_felt252('INVALID_TX');
        0
    }
}

fn execute_calls(mut calls: Span<Call>) -> Array<Span<felt252>> {
    let mut result = ArrayTrait::new();
    loop {
        match calls.pop_front() {
            Option::Some(call) => {
                let mut res = call_contract_syscall(
                    address: *call.to,
                    entry_point_selector: *call.selector,
                    calldata: *call.calldata,
                )
                    .unwrap_syscall();
                result.append(res);
            },
            Option::None => { break; },
        };
    }
    result
}
