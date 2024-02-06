use braavos_account::sha256::sha256::{get_h, get_k, sha256_inner};

fn sha256_u32(mut data: Array<u32>, padding: u32) -> Span<felt252> {
    let data_len: u32 = (data.len() * 4 - padding) * 8;

    // add one
    if (padding == 0) {
        data.append(0x80000000);
    } else {
        let copy_len = data.len() - 1;
        let last = *data.at(copy_len);
        let mut data_tmp = array![];
        let mut i = 0;
        loop {
            if (i >= copy_len) {
                break;
            }
            data_tmp.append(*data.at(i));
            i += 1;
        };
        if (padding == 3) {
            data_tmp.append(last | 0x800000);
        } else if (padding == 2) {
            data_tmp.append(last | 0x8000);
        } else if (padding == 1) {
            data_tmp.append(last | 0x80);
        }
        data = data_tmp;
    }
    // add padding
    loop {
        if (16 * ((data.len() - 1) / 16 + 1)) - 1 == data.len() {
            break;
        }
        data.append(0);
    };

    // add length to the end
    data.append(data_len);

    let h = get_h();
    let k = get_k();
    let mut res = sha256_inner(data.span(), 0, k.span(), h.span());

    let mut arr: Array<felt252> = array![];
    loop {
        match res.pop_front() {
            Option::Some(elem) => { arr.append((*elem).into()); },
            Option::None => { break; },
        };
    };
    arr.span()
}
