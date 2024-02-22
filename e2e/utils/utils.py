import base64
from collections import namedtuple
from functools import reduce
import json
import pytest

from pathlib import Path
import subprocess
from typing import Dict, List, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    Prehashed,
)
from poseidon_py.poseidon_hash import poseidon_hash_many
from starknet_py.hash.casm_class_hash import compute_casm_class_hash
from starknet_py.hash.utils import compute_hash_on_elements
from starknet_py.net.account.account import AccountTransaction, Account, KeyPair
from starknet_py.net.client_models import (
    Call,
    ResourceBounds,
    TransactionExecutionStatus,
    TransactionReceipt,
)
from starknet_py.net.full_node_client import FullNodeClient
from starknet_py.hash.selector import get_selector_from_name
from starknet_py.hash.transaction import compute_deploy_account_transaction_hash
from starknet_py.hash.utils import message_signature
from starknet_py.net.schemas.gateway import CasmClassSchema
from starknet_py.net.models.chains import StarknetChainId

STARK_SIGNER_TYPE = 1
SECP256R1_SIGNER_TYPE = 2
MOA_SIGNER_TYPE = 4
WEBAUTHN_SIGNER_TYPE = 5

REQUIRED_SIGNER_STARK = 1
REQUIRED_SIGNER_STRONG = 2
REQUIRED_SIGNER_MULTISIG = 3

ETHER = 10**18
USDC = 10**6
ETH_TOKEN_ADDRESS = 0x49D36570D4E46F48E99674BD3FCC84644DDD6B96F7C741B1562B82F9E004DC7


def encode_string_as_hex(input: str):
    return hex(int.from_bytes(input.encode("ascii"), "big")).lstrip("0x")


def flatten_seq(x):
    return reduce(
        lambda target, elem: (target + flatten_seq(elem))
        if hasattr(elem, "__iter__") and not isinstance(elem, str) else
        (target + [elem]
         if isinstance(elem, int) else target + [int(elem, 16)]),
        x,
        [],
    )


def to_uint256(a):
    """Takes in value, returns uint256-ish tuple."""
    return (a & ((1 << 128) - 1), a >> 128)


def break_into_Nbit_chunks(large_integer, chunk_bit_size):
    # Define the mask to extract n-bits.
    bin_str = bin(large_integer).lstrip("0b")
    # padding = len(bin_str) % chunk_bit_size
    chunks = []

    # Append zeros to make the length of bin_str a multiple of n bits
    # if padding:
    #    bin_str += '0' * (chunk_bit_size - padding)
    for i in range(0, len(bin_str), chunk_bit_size):
        chunk = bin_str[i:i + chunk_bit_size]
        chunks.append(int(chunk, 2))

    return chunks, 0  # chunk_bit_size - padding


def sign_hash_stark(hash, stark_privk):
    return [STARK_SIGNER_TYPE, *message_signature(hash, stark_privk)]


def create_stark_signer(stark_privk: int, mock_est_fee=False):

    def sign_txn(txn: AccountTransaction):
        if not mock_est_fee or txn.version < 2**128:
            return sign_hash_stark(txn.calculate_hash(StarknetChainId.TESTNET),
                                   stark_privk)
        else:
            return [STARK_SIGNER_TYPE, 0, 0]

    return namedtuple("StarkSigner",
                      ["sign_transaction"])(lambda txn: sign_txn(txn))


def create_legacy_stark_signer(stark_privk: int, mock_est_fee=False):

    def sign_txn(txn: AccountTransaction):
        if not mock_est_fee or txn.version < 2**128:
            return message_signature(
                txn.calculate_hash(StarknetChainId.TESTNET),
                stark_privk,
            )
        else:
            return [0, 0]

    return namedtuple("StarkSigner",
                      ["sign_transaction"])(lambda txn: sign_txn(txn))


def generate_secp256r1_keypair():
    ecc_key = ec.generate_private_key(ec.SECP256R1())
    pk_x_uint256 = to_uint256(ecc_key.public_key().public_numbers().x)
    pk_y_uint256 = to_uint256(ecc_key.public_key().public_numbers().y)

    return ecc_key, (pk_x_uint256, pk_y_uint256)


def sign_hash_secp256r1(hash,
                        ecc_key: ec.EllipticCurvePrivateKey,
                        legacy=False):
    hash_bytes = hash.to_bytes((hash.bit_length() + 7) // 8,
                               byteorder="big",
                               signed=False)
    pub_key = ecc_key.public_key()
    pk_x_uint256 = to_uint256(pub_key.public_numbers().x)
    pk_y_uint256 = to_uint256(pub_key.public_numbers().y)
    sig = ecc_key.sign(
        hash_bytes,
        ec.ECDSA(Prehashed(hashes.SHAKE256(len(hash_bytes)))),
    )
    r, s = decode_dss_signature(sig)
    return [
        *([SECP256R1_SIGNER_TYPE, *pk_x_uint256, *pk_y_uint256]
          if legacy is False else []), *to_uint256(r), *to_uint256(s)
    ]


def create_secp256r1_signer(ecc_key: ec.EllipticCurvePrivateKey,
                            legacy=False,
                            mock_est_fee=False):

    def sign_txn(txn: AccountTransaction):
        if mock_est_fee and txn.version >= 2**128:
            return [
                *([SECP256R1_SIGNER_TYPE, *[0, 0], *[0, 0]
                   ]  # *pk_x_uint256, *pk_y_uint256]
                  if legacy is False else []),
                *[0, 0],
                *[0, 0],  # *to_uint256(r), *to_uint256(s)
            ]

        txn_hash = txn.calculate_hash(StarknetChainId.TESTNET)
        return sign_hash_secp256r1(txn_hash, ecc_key, legacy)

    return namedtuple('Secp256r1Signer',
                      ['sign_transaction'])(lambda txn: sign_txn(txn))


def u8s_to_u32s_padded(array_u8):
    array_u32 = []
    padding = 0
    for i in range(0, len(array_u8), 4):
        # Extract 4 bytes, or less if not available
        as_u32_bytes = array_u8[i:i + 4]
        # Pad with zeros if less than 4 bytes
        while len(as_u32_bytes) < 4:
            padding += 1
            as_u32_bytes.append(0)
        # Convert 4 bytes to a single u32 integer
        u32 = as_u32_bytes[3] | (as_u32_bytes[2] << 8) | (
            as_u32_bytes[1] << 16) | (as_u32_bytes[0] << 24)
        array_u32.append(u32)
    return array_u32, padding


def sign_hash_webauthn(hash,
                       ecc_key: ec.EllipticCurvePrivateKey,
                       force_cairo_impl=False):
    rp_id = b'braavos.app'
    rp_id_digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    rp_id_digest.update(rp_id)
    rp_id_hash_bytes = rp_id_digest.finalize()
    auth_data_flags = (0b101).to_bytes(1, 'big')
    sign_count = (0).to_bytes(4, 'big')
    auth_data_bytes = rp_id_hash_bytes + auth_data_flags + sign_count

    hash_byte_padded_len = (hash.bit_length() + 7) // 8
    hash_bytes = hash.to_bytes(
        hash_byte_padded_len,
        byteorder="big",
        signed=False,
    )
    base64_challenge = base64.urlsafe_b64encode(hash_bytes).rstrip(b'=')
    base64_challenge_ascii = base64_challenge.decode('ascii')
    client_data = {
        "type": "webauthn.get",
        "challenge": base64_challenge_ascii,
        "origin": "https://e2e.test",
        "crossOrigin": False,
    }
    client_data_bytes = json.dumps(
        client_data,
        separators=(',', ':'),
    ).encode('ascii')
    challenge_offset = client_data_bytes.find(base64_challenge)
    cdata_digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    cdata_digest.update(client_data_bytes)
    cdata_hash_bytes = cdata_digest.finalize()
    authdata_cdata_concat_bytes = auth_data_bytes + cdata_hash_bytes
    authdata_cdata_digest = hashes.Hash(hashes.SHA256(),
                                        backend=default_backend())
    authdata_cdata_digest.update(authdata_cdata_concat_bytes)
    authdata_cdata_hash = authdata_cdata_digest.finalize()
    pub_key = ecc_key.public_key()
    pk_x_uint256 = to_uint256(pub_key.public_numbers().x)
    pk_y_uint256 = to_uint256(pub_key.public_numbers().y)
    sig = ecc_key.sign(
        authdata_cdata_hash,
        ec.ECDSA(Prehashed(hashes.SHAKE256(len(authdata_cdata_hash)))),
    )
    r, s = decode_dss_signature(sig)
    hash_binstr = "".join([f"{byte:08d}" for byte in hash_bytes])
    assert len(hash_binstr) % 8 == 0, 'byte alignment expected'
    hash_6bit_align = (6 - (len(hash_binstr) % 6)) % 6
    base64_padding = 0 if hash_6bit_align == 0 else 2**hash_6bit_align
    cdata_u32s = u8s_to_u32s_padded([b for b in client_data_bytes])
    adata_u32s = u8s_to_u32s_padded([b for b in auth_data_bytes])
    ret = [
        WEBAUTHN_SIGNER_TYPE, *pk_x_uint256, *pk_y_uint256,
        len(adata_u32s[0]), *adata_u32s[0], adata_u32s[1],
        len(cdata_u32s[0]), *cdata_u32s[0], cdata_u32s[1], challenge_offset,
        len(base64_challenge_ascii), base64_padding, *to_uint256(r),
        *to_uint256(s), 1 if force_cairo_impl else 0
    ]
    return ret


def create_webauthn_signer(ecc_key: ec.EllipticCurvePrivateKey,
                           force_cairo_impl: bool = False,
                           mock_est_fee=False):

    def sign_txn(txn: AccountTransaction, force_cairo_impl: bool = False):
        if mock_est_fee and txn.version >= 2**128:
            return [
                WEBAUTHN_SIGNER_TYPE,
                *[0, 0],
                *[0, 0],  # *pk_x_uint256, *pk_y_uint256,
                0,
                0,  # len(auth_data_bytes), *([byte for byte in auth_data_bytes]), auth data padding
                0,
                0,  # len(client_data_bytes), *([byte for byte in client_data_bytes]), cdata padding
                0,
                0,
                0,  # challenge_offset, len(base64_challenge_ascii), base64_padding,
                *[0, 0],
                *[0, 0],
                0,  # *to_uint256(r), *to_uint256(s), 1 if force_cairo_impl else 0
            ]

        txn_hash = txn.calculate_hash(StarknetChainId.TESTNET)
        return sign_hash_webauthn(txn_hash, ecc_key, force_cairo_impl)

    return namedtuple(
        'WebauthnSigner',
        ['sign_transaction'
         ])(lambda txn: sign_txn(txn, force_cairo_impl=force_cairo_impl))


def create_multisig_signers(signers):
    return namedtuple('MultisigSigner', [
        'sign_transaction'
    ])(lambda txn:
       [item for signer in signers for item in signer.sign_transaction(txn)])


def create_multisig_signer(signer_1, signer_2):
    return namedtuple("MultisigSigner", ["sign_transaction"])(lambda txn: [
        *signer_1.sign_transaction(txn),
        *signer_2.sign_transaction(txn),
    ])


def cairo0_deployment_signer(deploy_txn, account_address, stark_keypair,
                             account_cairo0_chash, secp256r1_pubk):
    deploy_txn_hash = compute_deploy_account_transaction_hash(
        version=deploy_txn.version,
        contract_address=account_address,
        class_hash=deploy_txn.class_hash,
        constructor_calldata=deploy_txn.constructor_calldata,
        max_fee=deploy_txn.max_fee,
        nonce=deploy_txn.nonce,
        salt=stark_keypair.public_key,
        chain_id=StarknetChainId.TESTNET,
    )
    depl_hash = compute_hash_on_elements([
        deploy_txn_hash,
        account_cairo0_chash,
        *secp256r1_pubk,
    ])
    return [
        *message_signature(depl_hash, stark_keypair.private_key),
        account_cairo0_chash,
        *secp256r1_pubk,
    ]


def txn_receipt_contains_event(
    txn_receipt: TransactionReceipt,
    event_keys: List[int],
    event_data: List[int] = [],
    match_data: bool = False,
) -> bool:
    for evt in txn_receipt.events:
        if set(event_keys).issubset(set(
                evt.keys)) and (match_data == False
                                or set(event_data).issubset(set(evt.data))):
            return True
    return False


async def assert_execute_fails_with_signer(account: Account, call: Call,
                                           signer, expected_error):
    prev_signer = account.signer
    account.signer = signer
    with pytest.raises(
            Exception,
            match=encode_string_as_hex(expected_error)
            if expected_error is not None and False else None,
    ) as e:
        exec = await account.execute(
            calls=call,
            #            max_fee=int(0.1 * 10**18),
            auto_estimate=True,
            # cairo_version=1,
        )

    #        await account.client.wait_for_tx(exec.transaction_hash)
    account.signer = prev_signer


def compute_myswap_cl_pool_key(token1_addr: int, token2_addr: int, fee: int):
    return poseidon_hash_many([token1_addr + token2_addr, fee])


def compute_myswap_cl_to_usdc_price(
    target_rate_usdc_for_token,
    token_decimal,
    is_usdc_token0,
    target_decimals=6,
):
    # USDC decimals == 6
    # Target rate is in [USDC/TOKEN] units so amount[TOKEN] * target_rate[USDC/TOKEN] = amount[USDC]
    # Output rate is expected to be TOKEN A in terms of TOKEN B i.e. [TOKEN_B / TOKEN_A]  where addr(TOKEN A) < addr(TOKEN B)
    output_rate = (target_rate_usdc_for_token *
                   (10**target_decimals / 10**token_decimal))**(
                       -1 if is_usdc_token0 else 1) * (2**96)
    return int(output_rate)


async def execute_calls(account: Account,
                        calls: Union[Call, List[Call]],
                        max_fee=None,
                        execute_v3=False):
    if execute_v3 is False:
        if max_fee is None:
            invoke_txn = await account.sign_invoke_v1_transaction(
                calls,
                max_fee=int(0.1 * 10**18),
            )
            invoke_est_fee = await account.sign_for_fee_estimate(invoke_txn)
            est_fee = await account.client.estimate_fee(invoke_est_fee)
            max_fee = est_fee.overall_fee + 25000 * est_fee.gas_price
        exec = await account.execute(
            calls,
            # cairo_version=cairo_version,
            max_fee=max_fee,
        )
    else:
        invoke_txn = await account.sign_invoke_v3_transaction(
            calls,
            l1_resource_bounds=ResourceBounds(
                max_amount=10**17,
                max_price_per_unit=1,
            ),
        )
        invoke_est_fee = await account.sign_for_fee_estimate(invoke_txn)
        est_fee = await account.client.estimate_fee(invoke_est_fee)
        max_fee = est_fee.overall_fee + 25000 * est_fee.gas_price
        exec = await account.execute_v3(
            calls,
            l1_resource_bounds=ResourceBounds(
                max_amount=int(max_fee / (100 * 10**9)),
                max_price_per_unit=100 * 10**9 + 1,
            ),
        )
    receipt = await account.client.wait_for_tx(exec.transaction_hash)
    assert receipt.execution_status == TransactionExecutionStatus.SUCCEEDED
    return receipt


async def is_account_signer(account: Account, signer_guid: int):
    account_signers: List[int] = await account.client.call_contract(
        Call(
            to_addr=account.address,
            selector=get_selector_from_name("get_signers"),
            calldata=[],
        ))
    assert signer_guid in account_signers, "signer guid not found in account"


def run_compile_command(command: List[str], sierra_artifact: Path,
                        casm_artifact: Path) -> Dict[str, any]:
    try:
        result: subprocess.CompletedProcess = subprocess.run(
            command, capture_output=True)
    except subprocess.CalledProcessError:
        # The inner command is responsible for printing the error message. No need to print the
        # stack trace of this script.
        raise Exception(message="Compilation failed.")

    if result is None:
        raise Exception("Compilation failed.")

    if result.returncode != 0:
        raise Exception(
            f"Compilation failed. {result.stdout.decode()}, {result.stderr.decode()}"
        )

    # Read and return the compilation result from the output.
    return sierra_artifact.read_text(), casm_artifact.read_text()


def get_contract_str(artifact_prefix: str) -> str:
    command = ["scarb", "build"]
    artifact_prefix = artifact_prefix
    return run_compile_command(
        command=command,
        sierra_artifact=Path(f"{artifact_prefix}.contract_class.json"),
        casm_artifact=Path(f"{artifact_prefix}.compiled_contract_class.json"),
    )


async def declare_v2(client: FullNodeClient, account: Account,
                     sierra_path: str, casm_path: str):
    with open(sierra_path, "r") as f:
        sierra_content = f.read()
    with open(casm_path, "r") as f:
        casm_content = f.read()

    casm_chash = compute_casm_class_hash(CasmClassSchema().loads(casm_content))
    declare_signed_txn = await account.sign_declare_v2_transaction(
        compiled_contract=sierra_content,
        compiled_class_hash=casm_chash,
        max_fee=int(0.1 * 10**18),
    )
    decl = await client.declare(declare_signed_txn)
    await client.wait_for_tx(decl.transaction_hash)
    return decl.class_hash


def parse_calls_for_typed_data(calls):
    calls_parsed = []
    for call in calls:
        _data = {
            "To": call.to_addr,
            "Selector": call.selector,
            "Calldata": call.calldata,
        }
        calls_parsed.append(_data)

    return calls_parsed
