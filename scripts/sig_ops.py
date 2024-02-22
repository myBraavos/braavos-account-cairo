import requests

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
    Prehashed,
)

from starkware.starknet.compiler.compile import get_selector_from_name


def check_secp256r1_sig(txn_hash):
    chain_txn_raw = requests.get(
        f"https://alpha-mainnet.starknet.io/feeder_gateway/get_transaction?transactionHash={hex(txn_hash)}"
    ).json()
    account_address = int(chain_txn_raw["transaction"]["sender_address"], 16)
    block_num = chain_txn_raw.get("block_number", "pending")
    signer_id = int(chain_txn_raw["transaction"]["signature"][0], 16)
    signer_pub_key_raw = requests.post(
        f"https://alpha-mainnet.starknet.io/feeder_gateway/call_contract?blockNumber={block_num}",
        json={
            "signature": [],
            "contract_address": hex(account_address),
            "entry_point_selector": hex(get_selector_from_name("get_signer")),
            "calldata": [str(signer_id)],
        },
    ).json()["result"]
    signer_pub_key_raw = [int(x, 16) for x in signer_pub_key_raw]
    pub_x = signer_pub_key_raw[0] + (signer_pub_key_raw[1] << 128)
    pub_y = signer_pub_key_raw[2] + (signer_pub_key_raw[3] << 128)
    public_numbers = ec.EllipticCurvePublicNumbers(pub_x, pub_y, ec.SECP256R1())
    public_key = public_numbers.public_key(default_backend())

    sig_rs_raw = [int(x, 16) for x in chain_txn_raw["transaction"]["signature"][1:]]
    r = sig_rs_raw[0] + (sig_rs_raw[1] << 128)
    s = sig_rs_raw[2] + (sig_rs_raw[3] << 128)
    # Construct the public key point.
    encoded_sig = encode_dss_signature(r, s)
    message_hash_bytes = txn_hash.to_bytes(
        (txn_hash.bit_length() + 7) // 8, byteorder="big", signed=False
    )
    public_key.verify(
        encoded_sig,
        message_hash_bytes,
        ec.ECDSA(Prehashed(hashes.SHAKE256(len(message_hash_bytes)))),
    )
