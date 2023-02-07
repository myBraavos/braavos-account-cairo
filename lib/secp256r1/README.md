# secp256r1 ECDSA

Taken almost as-is from https://github.com/EulerSmile/common-ec-cairo adapted to
`secp256r1`. The main modification is to use `cairo-lang`'s data structures.

## Notes

This implementation is inefficient compared to `cairo-lang`'s implementation of ECDSA on
`secp256k1` due to extensive use of `bigint_div_mod` (i.e. for reduction)
