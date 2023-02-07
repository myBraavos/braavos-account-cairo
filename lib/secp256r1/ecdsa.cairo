from starkware.cairo.common.cairo_secp.bigint import (
    BASE,
    BigInt3,
    UnreducedBigInt5,
    UnreducedBigInt3,
)
from starkware.cairo.common.cairo_secp.ec import EcPoint
from starkware.cairo.common.math import assert_nn_le, assert_not_zero

from lib.secp256r1.param_def import (
    N0, N1, N2,
    GX0, GX1, GX2, GY0, GY1, GY2,
)
from lib.secp256r1.bigint import bigint_div_mod
from lib.secp256r1.ec import ec_add, ec_mul, verify_point

// Verifies that val is in the range [1, N).
func validate_signature_entry{range_check_ptr}(val: BigInt3) {
    assert_nn_le(val.d2, N2);
    assert_nn_le(val.d1, BASE - 1);
    assert_nn_le(val.d0, BASE - 1);

    if (val.d2 == N2) {
        if (val.d1 == N1) {
            assert_nn_le(val.d0, N0 - 1);
            return ();
        }
        assert_nn_le(val.d1, N1 - 1);
        return ();
    }

    if (val.d2 == 0) {
        if (val.d1 == 0) {
            // Make sure val > 0.
            assert_not_zero(val.d0);
            return ();
        }
    }
    return ();
}

// Verifies a ECDSA signature.
// We assume public_key_pt is on curve as signer was verified when added
// Soundness assumptions:
// * All the limbs of public_key_pt.x, public_key_pt.y, msg_hash are in the range [0, 3 * BASE).
func secp256r1_verify_ecdsa{range_check_ptr}(
    public_key_pt: EcPoint, msg_hash: BigInt3, r: BigInt3, s: BigInt3
) {
    alloc_locals;
    validate_signature_entry(r);
    validate_signature_entry(s);

    let gen_pt = EcPoint(BigInt3(GX0, GX1, GX2), BigInt3(GY0, GY1, GY2));

    let N = BigInt3(N0, N1, N2);
    // Compute u1 and u2.
    let (u1: BigInt3) = bigint_div_mod(
        UnreducedBigInt5(
        d0=msg_hash.d0,
        d1=msg_hash.d1,
        d2=msg_hash.d2,
        d3=0,
        d4=0
        ),
        UnreducedBigInt3(
        d0=s.d0,
        d1=s.d1,
        d2=s.d2
        ),
        N,
    );

    let (u2: BigInt3) = bigint_div_mod(
        UnreducedBigInt5(
        d0=r.d0,
        d1=r.d1,
        d2=r.d2,
        d3=0,
        d4=0
        ),
        UnreducedBigInt3(
        d0=s.d0,
        d1=s.d1,
        d2=s.d2
        ),
        N,
    );

    let (gen_u1) = ec_mul(gen_pt, u1);
    let (pub_u2) = ec_mul(public_key_pt, u2);
    let (res) = ec_add(gen_u1, pub_u2);

    // The following assert also implies that res is not the zero point.
    assert res.x = r;

    return ();
}

func dummy_secp256r1_ecdsa_for_gas_fee{range_check_ptr}() -> () {
    let public_key_pt: EcPoint = EcPoint(
            x=BigInt3(
                d0=42777382219775096101484992,
                d1=9449389495556806005598229,
                d2=15391346295184681198220415,
            ),
            y=BigInt3(
                d0=3702352209106966425552919,
                d1=30573582502844647711662187,
                d2=1818880114566184684719572,
            )
        );

        // pedersen(b"dummy hash")
        let hash = BigInt3(
            d0=8880504667869362465582470,
            d1=71951553180754456105327651,
            d2=550345846109407064381700,
        );

        let r = BigInt3(
            d0=67061306386373668178390653,
            d1=30911540438108861883184440,
            d2=5766490690127844859062252,
        );

        let s = BigInt3(
            d0=42392106624914623069078766,
            d1=22641805182208186318245183,
            d2=13528013757477190678143234,
        );

        secp256r1_verify_ecdsa(public_key_pt, hash, r, s);
        return ();
}
