use core::iter::IntoIterator;
use core::sha256::{
    SHA256_INITIAL_STATE, append_zeros, compute_sha256_u32_array, sha256_state_handle_digest,
    sha256_state_handle_init,
};
use starknet::SyscallResultTrait;
use starknet::syscalls::sha256_process_block_syscall;

/// This function is based on the cairo core lib sha256 function compute_sha256_u32_array
/// but has a modified `add_sha256_padded_input` to match our input format.
fn sha256_u32(mut data: Array<u32>, last_word: u32, padding: u32) -> Span<felt252> {
    add_sha256_padded_input(ref data, last_word, padding);
    let mut state = sha256_state_handle_init(BoxTrait::new(SHA256_INITIAL_STATE));

    let mut input = data.span();
    while let Option::Some(chunk) = input.multi_pop_front() {
        state = sha256_process_block_syscall(state, *chunk).unwrap_syscall();
    }
    let [res1, res2, res3, res4, res5, res6, res7, res8] = sha256_state_handle_digest(state)
        .unbox();
    array![
        res1.into(),
        res2.into(),
        res3.into(),
        res4.into(),
        res5.into(),
        res6.into(),
        res7.into(),
        res8.into(),
    ]
        .span()
}

/// This function has the same purpose as core::sha256::panic_with_felt252 but
/// is optimized to our input format. The padding is defined as follows:
/// 1. Append a single bit with value 1 to the end of the array.
/// 2. Append zeros until the length of the array is 480 mod 512.
/// 3. Append the length of the array in bits as a 32-bit number.
/// Note: This implementation is based on cairo core lib's implementation but
/// differs from the standard which specifies that the length should be a
/// 64-bit number.
fn add_sha256_padded_input(ref data: Array<u32>, last_word: u32, padding: u32) {
    let input_len = data.len() + 1;
    if padding == 0 {
        data.append(last_word);
        data.append(0x80000000);
    } else {
        let pad = if padding == 1 {
            0x80
        } else if padding == 2 {
            0x8000
        } else if padding == 3 {
            0x800000
        } else {
            panic_with_felt252('ILLEGAL_PADDING');
            0
        };
        data.append(last_word + pad);
    }

    let mut remaining: felt252 = 16 - ((data.len() + 1) % 16).into();
    append_zeros(ref data, remaining);
    data.append(input_len * 32 - padding * 8);
}
