import asyncio
import base64
from collections import namedtuple
from functools import reduce
import json
import os
import pytest
import pytest_asyncio
import requests
import time

from pathlib import Path
import subprocess
from typing import Dict, List, Union
import random

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    Prehashed,
)
from poseidon_py.poseidon_hash import poseidon_hash_many
from starknet_py.constants import DEFAULT_DEPLOYER_ADDRESS, FEE_CONTRACT_ADDRESS
from starknet_py.hash.casm_class_hash import compute_casm_class_hash
from starknet_py.hash.class_hash import compute_class_hash
from starknet_py.hash.sierra_class_hash import compute_sierra_class_hash
from starknet_py.hash.utils import compute_hash_on_elements
from starknet_py.utils.iterable import ensure_iterable
from starknet_py.net.account.account import (
    AccountTransaction,
    Account,
    KeyPair,
    _execute_payload_serializer_v2,
    _parse_calls_v2,
)
from starknet_py.net.client_models import (
    Call,
    ResourceBounds,
    TransactionExecutionStatus,
    TransactionReceipt,
)
from starknet_py.net.full_node_client import FullNodeClient, _create_broadcasted_txn
from starknet_py.hash.address import compute_address
from starknet_py.hash.selector import get_selector_from_name
from starknet_py.hash.transaction import compute_deploy_account_transaction_hash
from starknet_py.hash.utils import message_signature, private_to_stark_key
from starknet_py.net.client_errors import ClientError
from starknet_py.net.schemas.gateway import (
    CasmClassSchema,
    ContractClassSchema,
    SierraCompiledContractSchema,
)
from starknet_py.net.models.chains import StarknetChainId
from starknet_py.net.models.transaction import DeployAccount
from starknet_py.contract import Contract
from starknet_py.net.udc_deployer.deployer import Deployer
from starknet_py.transaction_errors import TransactionRevertedError
from typed_data import TypedDataR1

STARK_SIGNER_TYPE = 1
SECP256R1_SIGNER_TYPE = 2
WEBAUTHN_SIGNER_TYPE = 5

REQUIRED_SIGNER_STARK = 1
REQUIRED_SIGNER_STRONG = 2
REQUIRED_SIGNER_MULTISIG = 3

ETHER = 10**18
USDC = 10**6
ETH_TOKEN_ADDRESS = 0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7
STRK_TOKEN_ADDRESS = 0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d


def encode_string_as_hex(input: str):
    return hex(int.from_bytes(input.encode('ascii'), 'big')).lstrip("0x")


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
    bin_str = bin(large_integer).lstrip('0b')
    # padding = len(bin_str) % chunk_bit_size
    chunks = []

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
    hash_bytes = hash.to_bytes(
        (hash.bit_length() + 7) // 8,
        byteorder="big",
        signed=False,
    )
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


def create_multisig_signer(signer_1, signer_2):
    return namedtuple('MultisigSigner', ['sign_transaction'])(lambda txn: [
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
                evt.keys)) and (match_data is False
                                or set(event_data).issubset(set(evt.data))):
            return True
    return False


async def assert_execute_fails_with_signer(account: Account, call: Call,
                                           signer, expected_error):
    prev_signer = account.signer
    account.signer = signer
    with pytest.raises(Exception,
                       match=encode_string_as_hex(expected_error)
                       if expected_error is not None and False else None) as _:
        _ = await account.execute(
            calls=call,
            auto_estimate=True,
        )

    account.signer = prev_signer


def compute_myswap_cl_pool_key(token1_addr: int, token2_addr: int, fee: int):
    return poseidon_hash_many([token1_addr + token2_addr, fee])


def compute_myswap_cl_to_usdc_price(target_rate_usdc_for_token, token_decimal,
                                    is_usdc_token0):
    # USDC decimals == 6
    # Target rate is in [USDC/TOKEN] units so amount[TOKEN] * target_rate[USDC/TOKEN] = amount[USDC]
    # Output rate is expected to be TOKEN A in terms of TOKEN B i.e. [TOKEN_B / TOKEN_A]  where addr(TOKEN A) < addr(TOKEN B)
    output_rate = (target_rate_usdc_for_token *
                   (10**6 / 10**token_decimal))**(-1 if is_usdc_token0 else
                                                  1) * (2**96)
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
    command = ['scarb', 'build']
    artifact_prefix = artifact_prefix
    return run_compile_command(
        command=command,
        sierra_artifact=Path(f"{artifact_prefix}.contract_class.json"),
        casm_artifact=Path(f"{artifact_prefix}.compiled_contract_class.json"))


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


@pytest.fixture(scope="module")
def event_loop():
    return asyncio.get_event_loop()


@pytest.fixture(scope="module")
def account_contracts_str():
    base_account_prefix = "target/dev/braavos_account_BraavosBaseAccount"
    account_prefix = "target/dev/braavos_account_BraavosAccount"
    base_account_sierra_str, base_account_casm_str = get_contract_str(
        base_account_prefix, )
    account_sierra_str, account_casm_str = get_contract_str(account_prefix, )
    return base_account_sierra_str, base_account_casm_str, account_sierra_str, account_casm_str


@pytest.fixture(scope="module")
def rate_service_contract_strings():
    rate_service_prefix = "services/rate_service/target/dev/rate_service_RateService"
    rate_service_sierra_str, rate_service_casm_str = get_contract_str(
        rate_service_prefix, )
    return rate_service_sierra_str, rate_service_casm_str


@pytest_asyncio.fixture(scope="module")
async def init_starknet():

    sn_devnet_url = "http://127.0.0.1:5050"
    sn_devnet_client = FullNodeClient(node_url=f"{sn_devnet_url}/rpc")

    sn_devnet_client_wait_for_tx_orig = sn_devnet_client.wait_for_tx

    async def wait_for_tx_short(tx_hash):
        return await sn_devnet_client_wait_for_tx_orig(tx_hash,
                                                       check_interval=0.1)

    sn_devnet_client.wait_for_tx = wait_for_tx_short

    # Katana
    '''
    | Account address |  0x5686a647a9cdd63ade617e0baf3b364856b813b508f03903eb58a7e622d5855
    | Private key     |  0x33003003001800009900180300d206308b0070db00121318d17b5e6262150b
    | Public key      |  0x4c0f884b8e5b4f00d97a3aad26b2e5de0c0c76a555060c837da2e287403c01d
    '''
    # devnet_account_address = 0x5686a647a9cdd63ade617e0baf3b364856b813b508f03903eb58a7e622d5855
    # devnet_account_privk = 0x33003003001800009900180300d206308b0070db00121318d17b5e6262150b
    # starknet-devnet-rs
    '''
    | Account address |  0x64b48806902a367c8598f4f95c305e8c1a1acba5f082d294a43793113115691
    | Private key     |  0x71d7bb07b9a64f6f78ac4c816aff4da9
    | Public key      |  0x39d9e6ce352ad4530a0ef5d5a18fd3303c3606a7fa6ac5b620020ad681cc33b
    '''
    devnet_account_address = 0x64b48806902a367c8598f4f95c305e8c1a1acba5f082d294a43793113115691
    devnet_account_privk = 0x71d7bb07b9a64f6f78ac4c816aff4da9

    sn_devnet_account = Account(
        address=devnet_account_address,
        client=sn_devnet_client,
        key_pair=KeyPair.from_private_key(devnet_account_privk),
        chain=StarknetChainId.TESTNET,
    )
    process = subprocess.Popen(
        [
            os.environ['STARKNET_DEVNET'],
            "--seed",
            "0",
            "--initial-balance",
            f"{10**6 * 10**18}",
        ],
        env=dict(os.environ),
        preexec_fn=os.setsid,
    )
    time.sleep(5)
    yield sn_devnet_url, sn_devnet_client, sn_devnet_account
    process.terminate()


@pytest_asyncio.fixture(scope="module")
def declare_deploy_v1():

    async def _declare_deploy_v1(compiled_contract_path,
                                 devnet_account,
                                 salt=0):
        with open(compiled_contract_path, mode="r",
                  encoding="utf8") as compiled_contract:
            declare_result = await Contract.declare(
                account=devnet_account,
                compiled_contract=compiled_contract.read(),
                max_fee=int(1e16))
            await devnet_account.client.wait_for_tx(declare_result.hash)
            deploy_result = await declare_result.deploy(max_fee=int(1e16),
                                                        constructor_args=[],
                                                        salt=salt)
            await devnet_account.client.wait_for_tx(deploy_result.hash)
            return deploy_result.deployed_contract

    return _declare_deploy_v1


@pytest_asyncio.fixture(scope="module")
def do_single_bypass_multicall(init_starknet, init_pricing_contract):
    pricing_contract_address, _, _ = init_pricing_contract

    async def _do_single_bypass_multicall(amount, token_address, account,
                                          bypass_signer):
        devnet_url, devnet_client, devnet_account = init_starknet
        temp = account.signer
        account.signer = bypass_signer

        # multicall is an approve + call to configured contract
        approve_bypass_call = Call(
            to_addr=token_address,
            selector=get_selector_from_name("approve"),
            calldata=[pricing_contract_address, *to_uint256(amount)])
        custom_call = Call(
            to_addr=pricing_contract_address,
            selector=get_selector_from_name("get_average_price"),
            calldata=[0, 0],
        )

        exec_txn = await account.execute(
            calls=[
                approve_bypass_call,
                custom_call,
            ],
            max_fee=int(0.1 * 10**18),
        )
        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

        account.signer = temp

    return _do_single_bypass_multicall


@pytest_asyncio.fixture(scope="module")
def do_double_bypass_multicall(init_starknet, init_pricing_contract):
    pricing_contract_address, _, _ = init_pricing_contract

    async def _do_double_bypass_multicall(amount1, token_address1, amount2,
                                          token_address2, account,
                                          bypass_signer):
        devnet_url, devnet_client, devnet_account = init_starknet
        temp = account.signer
        account.signer = bypass_signer

        # multicall is an approve + call to configured contract
        approve_bypass_call1 = Call(
            to_addr=token_address1,
            selector=get_selector_from_name("approve"),
            calldata=[pricing_contract_address, *to_uint256(amount1)])
        approve_bypass_call2 = Call(
            to_addr=token_address2,
            selector=get_selector_from_name("approve"),
            calldata=[pricing_contract_address, *to_uint256(amount2)])
        custom_call = Call(
            to_addr=pricing_contract_address,
            selector=get_selector_from_name("get_average_price"),
            calldata=[0, 0],
        )

        exec_txn = await account.execute(
            calls=[
                approve_bypass_call1,
                approve_bypass_call2,
                custom_call,
            ],
            max_fee=int(0.1 * 10**18),
        )
        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

        account.signer = temp

    return _do_double_bypass_multicall


@pytest_asyncio.fixture(scope="module")
def do_bypass(init_starknet):

    async def _do_bypass(token, amount, account, bypass_signer, call_type):
        devnet_url, devnet_client, devnet_account = init_starknet
        temp = account.signer
        account.signer = bypass_signer

        transfer_bypass_call = Call(
            to_addr=token,
            selector=get_selector_from_name(call_type),
            calldata=[devnet_account.address, *to_uint256(amount)])
        exec_txn = await account.execute(
            calls=transfer_bypass_call,
            max_fee=int(0.1 * 10**18),
        )
        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

        account.signer = temp

    return _do_bypass


@pytest_asyncio.fixture(scope="module")
def set_and_assert_high_threshold(init_starknet):

    async def _set_and_assert_high_threshold(high_threshold, account):
        _, devnet_client, _ = init_starknet
        set_withdrawal_limit_high_call = Call(
            to_addr=account.address,
            selector=get_selector_from_name('set_withdrawal_limit_high'),
            calldata=[high_threshold])
        exec_txn = await account.execute(
            calls=set_withdrawal_limit_high_call,
            max_fee=int(0.1 * 10**18),
        )

        await devnet_client.wait_for_tx(exec_txn.transaction_hash)
        exec_txn_receipt = await devnet_client.get_transaction_receipt(
            exec_txn.transaction_hash)
        assert txn_receipt_contains_event(
            exec_txn_receipt,
            [get_selector_from_name("WithdrawalLimitHighSet")],
            [high_threshold],
            True,
        ) is True, "no withdrawal limit set"

    return _set_and_assert_high_threshold


@pytest_asyncio.fixture(scope="module")
def set_and_assert_low_threshold(init_starknet):

    async def _set_and_assert_low_threshold(low_threshold, account):
        _, devnet_client, _ = init_starknet
        set_withdrawal_limit_low_call = Call(
            to_addr=account.address,
            selector=get_selector_from_name('set_withdrawal_limit_low'),
            calldata=[low_threshold])
        exec_txn = await account.execute(
            calls=set_withdrawal_limit_low_call,
            max_fee=int(0.1 * 10**18),
        )

        await devnet_client.wait_for_tx(exec_txn.transaction_hash)
        exec_txn_receipt = await devnet_client.get_transaction_receipt(
            exec_txn.transaction_hash)
        assert txn_receipt_contains_event(
            exec_txn_receipt,
            [get_selector_from_name("WithdrawalLimitLowSet")],
            [low_threshold],
            True,
        ) is True, "no withdrawal limit set"

    return _set_and_assert_low_threshold


@pytest_asyncio.fixture(scope="module")
def declare_v1():

    async def _declare_v1(compiled_contract_path, devnet_account):
        client = devnet_account.client
        """ declare contract from a compiled .json"""
        with open(compiled_contract_path, mode="r",
                  encoding="utf8") as compiled_contract:
            compiled_contract_content = compiled_contract.read()
            declare_tx = await devnet_account.sign_declare_v2_transaction(
                compiled_contract=compiled_contract_content,
                max_fee=int(0.1 * 10**18),
            )
            chash = compute_class_hash(ContractClassSchema().loads(
                compiled_contract_content, unknown="exclude"))
            decl = await client.declare(transaction=declare_tx)
            await client.wait_for_tx(decl.transaction_hash)
            return chash

    return _declare_v1


@pytest_asyncio.fixture(scope="module")
def generate_token(init_starknet, declare_deploy_v1):

    async def _generate_token(name, decimals, salt):
        devnet_url, devnet_client, devnet_account = init_starknet
        devnet_account: Account
        devnet_client: FullNodeClient
        res = await declare_deploy_v1("e2e/ERC20.json",
                                      devnet_account,
                                      salt=salt)
        res: Contract
        exec_tx = await devnet_account.execute(
            Call(
                to_addr=res.address,
                selector=get_selector_from_name("initialize"),
                calldata=[4, name, name, decimals, devnet_account.address],
            ),
            max_fee=int(0.1 * 10**18),
        )
        await devnet_client.wait_for_tx(exec_tx.transaction_hash)

        mint_tx = await devnet_account.execute(
            Call(
                to_addr=res.address,
                selector=get_selector_from_name("permissionedMint"),
                calldata=[
                    devnet_account.address,
                    *(to_uint256(ETHER * 10000)),
                ],
            ),
            max_fee=int(0.1 * 10**18),
        )
        await devnet_client.wait_for_tx(mint_tx.transaction_hash)

        return res

    return _generate_token


@pytest_asyncio.fixture(scope="module")
async def init_pricing_contract(init_starknet):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_account: Account
    devnet_client: FullNodeClient
    pricing_decl_chash = await declare_v2(
        devnet_client,
        devnet_account,
        "e2e/myswapv3_PoolPrice.sierra.json",
        "e2e/myswapv3_PoolPrice.casm.json",
    )

    deployment = Deployer().create_contract_deployment(
        class_hash=pricing_decl_chash,
        salt=0,
        cairo_version=1,
    )
    exec = await devnet_account.execute(deployment.call, auto_estimate=True)
    await devnet_client.wait_for_tx(exec.transaction_hash)

    # Setup pricing contract
    exec = await devnet_account.execute(
        Call(to_addr=deployment.address,
             selector=get_selector_from_name("initializer"),
             calldata=[devnet_account.address, 0x31337]),
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec.transaction_hash)

    mock_decl_chash = await declare_v2(devnet_client, devnet_account,
                                       "e2e/price_contract_test.sierra.json",
                                       "e2e/price_contract_test.casm.json")

    # Upgrade to mock
    exec = await devnet_account.execute(
        Call(to_addr=deployment.address,
             selector=get_selector_from_name("upgrade"),
             calldata=[mock_decl_chash]),
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec.transaction_hash)

    async def _set_price(pool_key, seconds_ago, price):
        set_exec = await devnet_account.execute(
            Call(to_addr=deployment.address,
                 selector=get_selector_from_name("set_price_for_pool_key"),
                 calldata=[pool_key, seconds_ago, *to_uint256(price)]),
            max_fee=int(0.1 * 10**18),
        )
        await devnet_client.wait_for_tx(set_exec.transaction_hash)

    async def _get_price(pool_key, seconds_ago):
        return await devnet_client.call_contract(
            Call(to_addr=deployment.address,
                 selector=get_selector_from_name("get_average_price"),
                 calldata=[pool_key, seconds_ago]), )

    USDC_ADDR = 0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8
    await _set_price(
        compute_myswap_cl_pool_key(int(FEE_CONTRACT_ADDRESS, 16), USDC_ADDR,
                                   500), 86400,
        compute_myswap_cl_to_usdc_price(target_rate_usdc_for_token=100 // 1,
                                        token_decimal=18,
                                        is_usdc_token0=False))

    STARK_ADDR = 0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d
    await _set_price(
        compute_myswap_cl_pool_key(STARK_ADDR, USDC_ADDR, 500), 86400,
        compute_myswap_cl_to_usdc_price(target_rate_usdc_for_token=100 // 1,
                                        token_decimal=18,
                                        is_usdc_token0=False))
    return deployment.address, _set_price, _get_price


@pytest_asyncio.fixture(scope="module")
async def usdc_token(generate_token):
    return await generate_token('USDC', 6, salt=0)


@pytest_asyncio.fixture(scope="module")
async def mock_usdc_threshold_token(generate_token):
    return await generate_token('USDC2', 6, salt=2)


@pytest_asyncio.fixture(scope="module")
async def pepe_token(generate_token):
    return await generate_token('PEPE', 18, salt=1)


@pytest_asyncio.fixture(scope="module")
async def sha256_cairo0_declare(init_starknet):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_account: Account
    devnet_client: FullNodeClient
    with open("e2e/sha256_cairo0.json", mode="r",
              encoding="utf8") as compiled_contract:
        compiled_contract_content = compiled_contract.read()
        chash = compute_class_hash(ContractClassSchema().loads(
            compiled_contract_content, unknown="exclude"))
        declare_tx = await devnet_account.sign_declare_v1_transaction(
            compiled_contract=compiled_contract_content,
            max_fee=int(0.1 * 10**18),
        )
        decl = await devnet_client.declare(transaction=declare_tx)
        await devnet_client.wait_for_tx(decl.transaction_hash)
        return chash


@pytest_asyncio.fixture(scope="module")
async def upgrade_test_declare(init_starknet):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_account: Account
    devnet_client: FullNodeClient

    happy_path_chash = await declare_v2(
        devnet_client,
        devnet_account,
        "./e2e/upgrade_test.sierra.json",
        "./e2e/upgrade_test.casm.json",
    )

    fail_src6_chash = await declare_v2(
        devnet_client,
        devnet_account,
        "./e2e/upgrade_test_fail_src6.sierra.json",
        "./e2e/upgrade_test_fail_src6.casm.json",
    )
    return happy_path_chash, fail_src6_chash


@pytest_asyncio.fixture(scope="module")
async def account_declare(init_starknet, account_contracts_str,
                          sha256_cairo0_declare):
    _ = sha256_cairo0_declare
    base_account_sierra_str, base_account_casm_str, account_sierra_str, account_casm_str = account_contracts_str
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    devnet_account: Account

    account_chash = compute_casm_class_hash(
        CasmClassSchema().loads(account_casm_str))
    account_sierra_chash = compute_sierra_class_hash(
        SierraCompiledContractSchema().loads(account_sierra_str,
                                             unknown="exclude"))
    declare_signed_txn = await devnet_account.sign_declare_v2_transaction(
        compiled_contract=account_sierra_str,
        compiled_class_hash=account_chash,
        max_fee=int(0.1 * 10**18),
    )
    account_decl = await devnet_client.declare(declare_signed_txn)
    await devnet_client.wait_for_tx(account_decl.transaction_hash)
    base_account_chash = compute_casm_class_hash(
        CasmClassSchema().loads(base_account_casm_str))
    base_account_sierra_chash = compute_sierra_class_hash(
        SierraCompiledContractSchema().loads(base_account_sierra_str,
                                             unknown="exclude"))
    declare_signed_txn = await devnet_account.sign_declare_v2_transaction(
        compiled_contract=base_account_sierra_str,
        compiled_class_hash=base_account_chash,
        max_fee=int(0.1 * 10**18),
    )
    base_account_decl = await devnet_client.declare(declare_signed_txn)
    await devnet_client.wait_for_tx(base_account_decl.transaction_hash)

    with open("e2e/account_cairo0.json", mode="r",
              encoding="utf8") as compiled_contract:
        compiled_contract_content = compiled_contract.read()
        declare_tx = await devnet_account.sign_declare_v1_transaction(
            compiled_contract=compiled_contract_content,
            max_fee=int(0.1 * 10**18),
        )
        account_cairo0_chash = compute_class_hash(ContractClassSchema().loads(
            compiled_contract_content, unknown="exclude"))
        decl = await devnet_client.declare(transaction=declare_tx)
        await devnet_client.wait_for_tx(decl.transaction_hash)

    with open("e2e/proxy_cairo0.json", mode="r",
              encoding="utf8") as compiled_contract:
        compiled_contract_content = compiled_contract.read()
        declare_tx = await devnet_account.sign_declare_v1_transaction(
            compiled_contract=compiled_contract_content,
            max_fee=int(0.1 * 10**18),
        )
        proxy_cairo0_chash = compute_class_hash(ContractClassSchema().loads(
            compiled_contract_content, unknown="exclude"))
        decl = await devnet_client.declare(transaction=declare_tx)
        await devnet_client.wait_for_tx(decl.transaction_hash)

    return account_sierra_chash, base_account_sierra_chash, account_cairo0_chash, proxy_cairo0_chash


@pytest_asyncio.fixture(scope="module")
async def account_deployer(
    init_starknet,
    account_declare,
    usdc_token,
    init_pricing_contract,
):
    account_chash, base_account_chash, _, _ = account_declare
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    devnet_account: Account

    def default_deployment_signer(
        stark_keypair: KeyPair,
        deploy_txn: DeployAccount,
        address: int,
        strong_signer_type=0,
        secp256r1_signer=[0, 0, 0, 0],
        multisig_threshold=0,
        withdrawal_limit_low=0,
        eth_fee_rate=0,
        stark_fee_rate=0,
    ):
        secp256r1_signer = [0, 0, 0, 0
                            ] if secp256r1_signer is None else secp256r1_signer
        deploy_txn_hash = compute_deploy_account_transaction_hash(
            version=deploy_txn.version,
            contract_address=address,
            class_hash=deploy_txn.class_hash,
            constructor_calldata=deploy_txn.constructor_calldata,
            max_fee=deploy_txn.max_fee,
            nonce=deploy_txn.nonce,
            salt=stark_keypair.public_key,
            chain_id=StarknetChainId.TESTNET,
        )
        aux_hash = poseidon_hash_many([
            account_chash,
            strong_signer_type,
            *secp256r1_signer,
            multisig_threshold,
            withdrawal_limit_low,
            eth_fee_rate,
            stark_fee_rate,
            StarknetChainId.TESTNET,
        ])
        ret = [
            *message_signature(deploy_txn_hash, stark_keypair.private_key),
            account_chash,
            strong_signer_type,
            *secp256r1_signer,
            multisig_threshold,
            withdrawal_limit_low,
            eth_fee_rate,
            stark_fee_rate,
            StarknetChainId.TESTNET,
            *message_signature(aux_hash, stark_keypair.private_key),
        ]
        return ret

    async def _account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_thresh,
        withdrawal_limit_low=0,
        eth_fee_rate=0,
        stark_fee_rate=0,
        stark_pub_key_override=None,
        deploy_signer=None,
        is_webauthn=False,
        erc20_address_to_transfer=None,
    ):
        stark_keypair = KeyPair.from_private_key(stark_privk)
        stark_pubk = stark_pub_key_override if stark_pub_key_override is not None else stark_keypair.public_key
        ctor_calldata = [stark_pubk]
        account_address = compute_address(
            class_hash=base_account_chash,
            salt=stark_pubk,
            constructor_calldata=ctor_calldata,
        )

        for fee_token in [ETH_TOKEN_ADDRESS, STRK_TOKEN_ADDRESS]:
            exec = await devnet_account.execute(
                Call(
                    to_addr=fee_token,
                    selector=get_selector_from_name("transfer"),
                    calldata=[
                        account_address,
                        105 * 10**18,
                        0,
                    ],
                ),
                max_fee=int(0.1 * 10**18),
            )
            await devnet_client.wait_for_tx(exec.transaction_hash)

        strong_signer_type = 0 if secp256r1_pubk in [
            None, [0, 0, 0, 0]
        ] else 5 if is_webauthn else 2

        if erc20_address_to_transfer is not None:
            exec = await devnet_account.execute(
                Call(
                    to_addr=erc20_address_to_transfer,
                    selector=get_selector_from_name("transfer"),
                    calldata=[
                        account_address,
                        10**20,
                        0,
                    ],
                ),
                max_fee=int(0.1 * 10**18),
            )
            await devnet_client.wait_for_tx(exec.transaction_hash)

        if deploy_signer is None:
            deploy_signer = namedtuple(
                "_DeploySigner",
                ["sign_transaction"
                 ])(lambda depl_account: default_deployment_signer(
                     stark_keypair,
                     depl_account,
                     account_address,
                     strong_signer_type,
                     secp256r1_pubk or [0, 0, 0, 0],
                     multisig_thresh,
                     withdrawal_limit_low,
                     eth_fee_rate,
                     stark_fee_rate,
                 ))
        deployer_account = Account(
            client=devnet_client,
            address=account_address,
            signer=deploy_signer,
        )

        signed_account_depl = await deployer_account.sign_deploy_account_v1_transaction(
            class_hash=base_account_chash,
            contract_address_salt=stark_pubk,
            constructor_calldata=ctor_calldata,
            auto_estimate=True,
        )
        account_depl = await devnet_client.deploy_account(signed_account_depl)
        await devnet_client.wait_for_tx(account_depl.transaction_hash)

        return Account(
            client=devnet_client,
            address=account_address,
            key_pair=stark_keypair,
            chain=StarknetChainId.TESTNET,
        ), account_depl.transaction_hash

    return _account_deployer


@pytest_asyncio.fixture(scope="module")
def clean_token_config(init_starknet, init_pricing_contract):
    pricing_contract_address, _, _ = init_pricing_contract

    async def _clean_token_config(account,
                                  fake_usdc_address=None,
                                  add_custom_call_double=False):
        _, devnet_client, _ = init_starknet

        # removing all tokens which are hardcoded in the contract but do not exists
        # on testnet

        call_data = [
            3,
            # usdt
            False,
            0x068f5c6a61780768455de69077e07e89787839bf8166decfbf92b645209c0fb8,
            0,
            False,
            # wbtc
            False,
            0x03fe2b97c1fd336e750087d68b9b867997fd64a2661ff3ca5a7c771641e8e7ac,
            0,
            False,
            # usdc
            False,
            0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8,
            0,
            False,
            # 0
        ] if fake_usdc_address is None else [
            4,
            # usdt
            False,
            0x068f5c6a61780768455de69077e07e89787839bf8166decfbf92b645209c0fb8,
            0,
            False,
            # wbtc
            False,
            0x03fe2b97c1fd336e750087d68b9b867997fd64a2661ff3ca5a7c771641e8e7ac,
            0,
            False,
            # usdc
            False,
            0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8,
            0,
            False,
            # fake token
            True,
            fake_usdc_address,
            9999,
            False,
            # 0
        ]

        if add_custom_call_double:
            call_data.extend([
                1, pricing_contract_address,
                get_selector_from_name('get_average_price'), 2
            ])
        else:
            call_data.extend([
                1, pricing_contract_address,
                get_selector_from_name('get_average_price'), 1
            ])

        update_config_call = Call(
            to_addr=account.address,
            selector=get_selector_from_name('update_rate_config'),
            calldata=call_data)
        exec_txn = await account.execute(
            calls=update_config_call,
            max_fee=int(0.1 * 10**18),
        )

        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    return _clean_token_config


@pytest_asyncio.fixture(scope="module")
def get_fee_rate(init_starknet):

    async def _get_fee_rate(account, token_name='eth'):
        _, devnet_client, _ = init_starknet

        get_rate_result = await devnet_client.call_contract(
            Call(
                to_addr=account.address,
                selector=get_selector_from_name(
                    "get_fee_token_rate" if token_name ==
                    "eth" else "get_stark_fee_token_rate"),
                calldata=[],
            ))
        return get_rate_result[0]

    return _get_fee_rate


@pytest_asyncio.fixture(scope="module")
def get_daily_spend(init_starknet):

    async def _get_daily_spend(account):
        _, devnet_client, _ = init_starknet

        daily_spend_result = await devnet_client.call_contract(
            Call(
                to_addr=account.address,
                selector=get_selector_from_name("get_daily_spend"),
                calldata=[],
            ))
        return daily_spend_result[0]

    return _get_daily_spend


@pytest_asyncio.fixture(scope="module")
def get_required_signer(init_starknet):

    async def _get_required_signer(account: Account,
                                   call: Call,
                                   fee=0,
                                   use_signer=None):
        _, devnet_client, _ = init_starknet
        devnet_client: FullNodeClient
        orig_signer = account.signer
        if use_signer is not None:
            account.signer = use_signer
        get_req_signer_txn = await account.sign_invoke_v1_transaction(
            Call(
                to_addr=account.address,
                selector=get_selector_from_name("get_required_signer"),
                calldata=[
                    1,
                    call.to_addr,
                    call.selector,
                    len(call.calldata),
                    *call.calldata,
                    # fee amount
                    fee,
                    # tx version
                    1
                ]),
            max_fee=int(0.1 * 10**18),
        )
        account.signer = orig_signer
        simul_res = await devnet_client.simulate_transactions(
            [get_req_signer_txn])
        return simul_res[0].transaction_trace.execute_invocation.calls[
            0].result[0]

    return _get_required_signer


@pytest_asyncio.fixture(scope="module")
def get_required_signer_of_bypass_call(init_starknet, get_required_signer):

    async def _get_required_signer_of_bypass_call(account: Account,
                                                  amount=0,
                                                  fee=0):
        _, devnet_client, devnet_account = init_starknet
        bypass_call = Call(
            to_addr=ETH_TOKEN_ADDRESS,
            selector=get_selector_from_name('transfer'),
            calldata=[devnet_account.address, *to_uint256(amount)],
        )
        return await get_required_signer(account, bypass_call, fee=fee)

    return _get_required_signer_of_bypass_call


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "secp256r1_keypair",
        "is_webauthn",
        "multisig_threshold",
        "withdrawal_limit_low",
        "fee_rate",
    ],
    [
        (None, False, 0, 0, 0),
        (generate_secp256r1_keypair(), False, 0, 0, 0),
        (generate_secp256r1_keypair(), False, 2, 0, 0),
        (generate_secp256r1_keypair(), True, 0, 0, 0),
        (generate_secp256r1_keypair(), True, 2, 0, 0),
        (
            generate_secp256r1_keypair(),
            False,
            0,
            50 * USDC,
            100 * USDC,
        ),
        (
            generate_secp256r1_keypair(),
            False,
            2,
            50 * USDC,
            100 * USDC,
        ),
        (
            generate_secp256r1_keypair(),
            True,
            0,
            50 * USDC,
            100 * USDC,
        ),
        (
            generate_secp256r1_keypair(),
            True,
            2,
            50 * USDC,
            100 * USDC,
        ),
    ],
    ids=[
        "basic_stark_signer",
        "with_secp256r1_no_multisig",
        "with_secp256r1_multisig",
        "with_webauthn_no_multisig",
        "with_webauthn_multisig",
        "with_secp256r1_no_multisig_with_thresh",
        "with_secp256r1_multisig_with_thresh",
        "with_webauthn_secp256r1_no_multisig_with_thresh",
        "with_webauthn_secp256r1_multisig_with_thresh",
    ],
)
async def test_deployment(
    init_starknet,
    account_declare,
    init_pricing_contract,
    get_required_signer,
    get_required_signer_of_bypass_call,
    clean_token_config,
    account_deployer,
    secp256r1_keypair,
    is_webauthn,
    multisig_threshold,
    withdrawal_limit_low,
    fee_rate,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    account_chash, _, _, _ = account_declare
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    stark_pubk = private_to_stark_key(stark_privk)
    secp256r1_pubk = None if secp256r1_keypair is None else flatten_seq(
        secp256r1_keypair[1])

    account, deploy_txn_hash = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_threshold,
        withdrawal_limit_low=withdrawal_limit_low,
        eth_fee_rate=fee_rate,
        stark_fee_rate=fee_rate,
        is_webauthn=is_webauthn)
    account: Account
    actual_chash = await devnet_client.get_class_hash_at(account.address)
    assert actual_chash == account_chash
    legacy_stark_signer = create_legacy_stark_signer(stark_privk)
    stark_signer = create_stark_signer(stark_privk)
    balanceof_call = Call(
        to_addr=int(FEE_CONTRACT_ADDRESS, 16),
        selector=get_selector_from_name('balanceOf'),
        calldata=[account.address],
    )
    deploy_txn_receipt = await devnet_client.get_transaction_receipt(
        deploy_txn_hash)
    assert txn_receipt_contains_event(
        deploy_txn_receipt,
        [get_selector_from_name("OwnerAdded"), stark_pubk],
        [STARK_SIGNER_TYPE],
    ) is True, "no stark added event emitted"

    if withdrawal_limit_low != 0:
        assert txn_receipt_contains_event(
            deploy_txn_receipt,
            [get_selector_from_name("WithdrawalLimitLowSet")],
            [withdrawal_limit_low],
            True,
        ) is True, "no withdrawal limit set"

    if secp256r1_keypair is None:
        # make sure stark signer can sign
        account.signer = stark_signer
        await execute_calls(account, balanceof_call)
        await execute_calls(account, balanceof_call, execute_v3=True)

        # make sure legacy stark signer can sign
        account.signer = legacy_stark_signer
        await execute_calls(account, balanceof_call)
        await execute_calls(account, balanceof_call, execute_v3=True)

        required_signer = await get_required_signer(account, balanceof_call)
        assert required_signer == REQUIRED_SIGNER_STARK
    else:
        if secp256r1_keypair is not None:
            assert txn_receipt_contains_event(
                deploy_txn_receipt,
                [
                    get_selector_from_name("OwnerAdded"),
                    poseidon_hash_many(secp256r1_pubk),
                ],
                [
                    WEBAUTHN_SIGNER_TYPE
                    if is_webauthn else SECP256R1_SIGNER_TYPE
                ],
            ) is True, "no secp256r1 signer added event emitted"

        # make sure stark signer can't sign
        await assert_execute_fails_with_signer(
            account,
            balanceof_call,
            stark_signer,
            'INVALID_SIG',
        )

        await assert_execute_fails_with_signer(
            account,
            balanceof_call,
            legacy_stark_signer,
            'INVALID_SIG',
        )

        strong_signer = create_webauthn_signer(
            secp256r1_keypair[0]) if is_webauthn else create_secp256r1_signer(
                secp256r1_keypair[0])
        await is_account_signer(
            account, poseidon_hash_many(flatten_seq(secp256r1_keypair[1])))
        if multisig_threshold == 0:
            account.signer = strong_signer
            await execute_calls(account, balanceof_call)
            await execute_calls(account, balanceof_call, execute_v3=True)
            required_signer = await get_required_signer(
                account, balanceof_call)
            assert required_signer == REQUIRED_SIGNER_STRONG, 'Wrong required signer'
        elif multisig_threshold == 2:
            # assert a single strong signer isn't enough when multisig is set
            await assert_execute_fails_with_signer(
                account,
                balanceof_call,
                strong_signer,
                'INVALID_SIG',
            )

            account.signer = create_multisig_signer(stark_signer,
                                                    strong_signer)
            await execute_calls(account, balanceof_call)
            await execute_calls(account, balanceof_call, execute_v3=True)
            required_signer = await get_required_signer(
                account, balanceof_call)
            assert required_signer == REQUIRED_SIGNER_MULTISIG, 'Wrong required signer'

        if withdrawal_limit_low > 0:
            await clean_token_config(account)
            required_signer_for_bypass = await get_required_signer_of_bypass_call(
                account, amount=0)
            assert required_signer_for_bypass == REQUIRED_SIGNER_STARK, 'Wrong required signer for bypass call'


@pytest.mark.asyncio
async def test_deployment_from_UDC(init_starknet, account_declare,
                                   account_contracts_str):
    devnet_url, devnet_client, devnet_account = init_starknet
    account_chash, base_account_chash, _, _ = account_declare
    base_account_sierra_str, _, _, _ = account_contracts_str

    devnet_account: Account
    devnet_client: FullNodeClient
    account_chash, _, _, _ = account_declare

    stark_privk = random.randint(1, 10**10)
    stark_pubk = private_to_stark_key(stark_privk)
    deployment_call = Call(
        to_addr=int(DEFAULT_DEPLOYER_ADDRESS, 16),
        selector=get_selector_from_name("deployContract"),
        calldata=[base_account_chash, stark_pubk, 0, 1, stark_pubk])
    expected_address = compute_address(class_hash=base_account_chash,
                                       salt=stark_pubk,
                                       constructor_calldata=[stark_pubk],
                                       deployer_address=0)

    secp256r1_kp = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_kp[1])

    def udc_depl_signer(txn: AccountTransaction):
        stark_sig = message_signature(
            txn.calculate_hash(StarknetChainId.TESTNET), stark_privk)
        aux_data = [
            account_chash,
            *[2, *secp256r1_pubk],  # Dummy SECP256R1 signer
            0,  # Multisig
            0,  # DWL low
            0,  # Eth fee rate
            0,  # STRK fee rate
            StarknetChainId.TESTNET,
        ]
        aux_hash = poseidon_hash_many(aux_data)
        aux_sig = message_signature(aux_hash, stark_privk)

        return [
            *stark_sig,
            *aux_data,
            *aux_sig,
        ]

    udc_deploy_signer = namedtuple(
        "UDCDeplSigner",
        ["sign_transaction"])(lambda depl_txn: udc_depl_signer(depl_txn))
    devnet_account_orig_signer = devnet_account.signer
    devnet_account.signer = udc_deploy_signer
    invoke_txn = await devnet_account.sign_invoke_v1_transaction(
        deployment_call, max_fee=int(0.1 * 10**18))

    # starknet.py == 0.18.3 doesn't support latest simulate response, so call it raw
    # simul_res = await devnet_client.simulate_transactions([invoke_txn], skip_validate=True)
    res = await devnet_client._client.call(
        method_name="simulateTransactions",
        params={
            "block_id": "pending",
            "simulation_flags": ["SKIP_VALIDATE"],
            "transactions": [_create_broadcasted_txn(transaction=invoke_txn)],
        },
    )
    txn_state_diff = res[0]["transaction_trace"]["state_diff"]
    assert txn_state_diff["deployed_contracts"][0]["address"] == hex(
        expected_address), "NOT DEPLOYED"
    assert poseidon_hash_many(secp256r1_pubk) in [
        int(x["value"], 16) for store_diff in txn_state_diff["storage_diffs"]
        for x in store_diff["storage_entries"]
    ]
    devnet_account.signer = devnet_account_orig_signer


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "src6_supported",
    ],
    [
        [True],
        [False],
    ],
    ids=[
        "src6_supported",
        "src6_not_supported",
    ],
)
async def test_upgrade(
    init_starknet,
    account_declare,
    account_deployer,
    upgrade_test_declare,
    src6_supported,
):
    devnet_client: FullNodeClient
    _, devnet_client, _ = init_starknet
    account_chash, _, _, _ = account_declare
    account_deployer = account_deployer
    upgrade_declare = upgrade_test_declare
    stark_privk = random.randint(1, 10**10)
    _ = private_to_stark_key(stark_privk)
    account, deploy_txn_hash = await account_deployer(stark_privk,
                                                      None,
                                                      0,
                                                      is_webauthn=False)
    account: Account
    if src6_supported:
        await account.execute(
            Call(to_addr=account.address,
                 selector=get_selector_from_name('upgrade'),
                 calldata=[upgrade_declare[0]]),
            auto_estimate=True,
        )
        migrated_storage = await devnet_client.get_storage_at(
            account.address, get_selector_from_name("storage_migration_ver"))
        assert migrated_storage == int.from_bytes(b'001.000.000', 'big')
    else:
        with pytest.raises(Exception):
            await account.execute(
                Call(to_addr=account.address,
                     selector=get_selector_from_name('upgrade'),
                     calldata=[upgrade_declare[1]]),
                auto_estimate=True,
            )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "secp256r1_keypair",
        "multisig_threshold",
        "stark_pub_key_override",
        "deploy_signer_override",
        "is_webauthn",
        "withdrawal_limit_low",
        "fee_rate",
        "expected_error",
    ],
    [
        (None, 0, 0, None, False, 0, 0, 'INVALID_DEPLOYMENT_SIG'),
        (None, 0, None,
         lambda chash: [31337, 31338, chash, 0, 0, 0, 0, 0, 31337, 31338],
         False, 0, 0, 'INVALID_DEPLOYMENT_SIG'),
        (None, 0, None, lambda chash: [0, 0, chash, 0, 0, 0, 0, 0, 0, 0],
         False, 0, 0, 'INVALID_DEPLOYMENT_SIG'),
        (None, 1, None, None, False, 0, 0, 'INVALID_MULTISIG_THRESHOLD'),
        (None, 2, None, None, False, 0, 0, 'INVALID_MULTISIG_THRESHOLD'),
        (generate_secp256r1_keypair(), 1, None, None, False, 0, 0,
         'INVALID_MULTISIG_THRESHOLD'),
        (generate_secp256r1_keypair(), 3, None, None, False, 0, 0,
         'INVALID_MULTISIG_THRESHOLD'),
        (generate_secp256r1_keypair(), 1, None, None, True, 0, 0,
         'INVALID_MULTISIG_THRESHOLD'),
        (generate_secp256r1_keypair(), 3, None, None, True, 0, 0,
         'INVALID_MULTISIG_THRESHOLD'),
        ((None, [1234, 4321, 5678, 8765]), 0, None, None, False, 0, 0, None),
        ((None, [1234, 4321, *generate_secp256r1_keypair()[1][1]
                 ]), 0, None, None, False, 0, 0, None),
        ((None, [*generate_secp256r1_keypair()[1][0], 5678, 8765
                 ]), 0, None, None, False, 0, 0, None),
        ((None, [1234, 4321, 5678, 8765]), 0, None, None, True, 0, 0, None),
        ((None, [1234, 4321, *generate_secp256r1_keypair()[1][1]
                 ]), 0, None, None, True, 0, 0, None),
        ((None, [*generate_secp256r1_keypair()[1][0], 5678, 8765
                 ]), 0, None, None, True, 0, 0, None),
        (None, 0, None, None, False, ETHER, ETHER,
         'INVALID_WITHDRAWAL_LIMIT_LOW'),
        (generate_secp256r1_keypair(), 0, None, None, False, ETHER, 0,
         'MISSING_RATE'),
    ],
    ids=[
        "stark_pub_key_is_0",
        "basic_stark_wrong_sig",
        "basic_stark_rs_zero_sig",
        "multisig_1_with_only_stark",
        "multisig_2_with_only_stark",
        "multisig_1_with_secp256r1",
        "multisig_3_with_secp256r1",
        "multisig_1_with_secp256r1_webauthn",
        "multisig_3_with_secp256r1_webauthn",
        "invalid_secp256r1_pubk",
        "invalid_secp256r1_pubk_x",
        "invalid_secp256r1_pubk_y",
        "invalid_secp256r1_pubk_webauthn",
        "invalid_secp256r1_pubk_x_webauthn",
        "invalid_secp256r1_pubk_y_webauthn",
        "low_withdrawal_limit_set_with_only_stark",
        "low_withdrawal_limit_set_without_fee_rate",
    ],
)
async def test_invalid_account_deployment(
    account_declare,
    account_deployer,
    secp256r1_keypair,
    multisig_threshold,
    stark_pub_key_override,
    deploy_signer_override,
    is_webauthn,
    withdrawal_limit_low,
    fee_rate,
    expected_error,
):
    account_chash, _, _, _ = account_declare
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    secp256r1_pubk = None if secp256r1_keypair is None else flatten_seq(
        secp256r1_keypair[1])
    if deploy_signer_override is not None:
        deploy_signer = namedtuple(
            "_DeploySigner",
            ["sign_transaction"
             ])(lambda depl_account: deploy_signer_override(account_chash))
    else:
        deploy_signer = None
    with pytest.raises(Exception):
        _ = await account_deployer(
            stark_privk,
            secp256r1_pubk,
            multisig_threshold,
            withdrawal_limit_low=withdrawal_limit_low,
            fee_rate=fee_rate,
            stark_pub_key_override=stark_pub_key_override,
            deploy_signer=deploy_signer,
            is_webauthn=is_webauthn)


@pytest.mark.asyncio
async def test_fail_initializer_after_deployment(account_deployer, ):
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account
    with pytest.raises(Exception):
        await account.execute(
            Call(to_addr=account.address,
                 selector=get_selector_from_name('initializer'),
                 calldata=[31337]),
            auto_estimate=True,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "secp256r1_keypair",
        "webauthn_secp256r1_keypair",
        "multisig_threshold",
    ],
    [
        (generate_secp256r1_keypair(), None, 0),
        (generate_secp256r1_keypair(), None, 2),
        (generate_secp256r1_keypair(), generate_secp256r1_keypair(), 0),
        (generate_secp256r1_keypair(), generate_secp256r1_keypair(), 2),
    ],
    ids=[
        "with_secp256r1_no_multisig",
        "with_secp256r1_multisig",
        "with_secp256r1_and_webauthn_no_multisig",
        "with_secp256r1_and_webauthn_multisig",
    ],
)
async def test_add_secp256r1_signer(
    init_starknet,
    account_deployer,
    secp256r1_keypair,
    webauthn_secp256r1_keypair,
    multisig_threshold,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    webauthn_secp256r1_pubk = None if webauthn_secp256r1_keypair is None else flatten_seq(
        webauthn_secp256r1_keypair[1])
    account, _ = await account_deployer(stark_privk,
                                        webauthn_secp256r1_pubk,
                                        0,
                                        is_webauthn=True)
    account: Account

    stark_signer = create_stark_signer(stark_privk)
    legacy_stark_signer = create_legacy_stark_signer(stark_privk)
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    webauthn_secp256r1_signer = None if webauthn_secp256r1_keypair is None else create_webauthn_signer(
        webauthn_secp256r1_keypair[0])

    if webauthn_secp256r1_signer is not None:
        account.signer = webauthn_secp256r1_signer

    add_secp256r1_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('add_secp256r1_signer'),
        calldata=[*secp256r1_pubk, SECP256R1_SIGNER_TYPE, multisig_threshold])
    exec_txn = await account.execute(
        calls=add_secp256r1_call,
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    exec_txn_receipt = await devnet_client.get_transaction_receipt(
        exec_txn.transaction_hash)
    assert txn_receipt_contains_event(
        exec_txn_receipt,
        [
            get_selector_from_name("OwnerAdded"),
            poseidon_hash_many(secp256r1_pubk),
        ],
        [
            SECP256R1_SIGNER_TYPE,
        ],
        match_data=True,
    ) is True, "no secp256r1 signer added event emitted"

    await is_account_signer(
        account, poseidon_hash_many(flatten_seq(secp256r1_keypair[1])))

    # stark signer can't sign a generic txn
    balanceof_call = Call(
        to_addr=int(FEE_CONTRACT_ADDRESS, 16),
        selector=get_selector_from_name('balanceOf'),
        calldata=[account.address],
    )
    await assert_execute_fails_with_signer(
        account,
        balanceof_call,
        stark_signer,
        'INVALID_SIG',
    )

    # legacy stark signer can't sign a generic txn
    await assert_execute_fails_with_signer(
        account,
        balanceof_call,
        legacy_stark_signer,
        'INVALID_SIG',
    )

    secp256r1_signer = create_secp256r1_signer(secp256r1_keypair[0])
    if multisig_threshold == 0:
        account.signer = secp256r1_signer
        await execute_calls(account, balanceof_call)

        if webauthn_secp256r1_signer is not None:
            # webauthn signer should also work in this case
            account.signer = webauthn_secp256r1_signer
            await execute_calls(account, balanceof_call)

            account.signer = create_webauthn_signer(
                webauthn_secp256r1_keypair[0], force_cairo_impl=True)
            await execute_calls(account, balanceof_call)
    elif multisig_threshold == 2:
        # Check that both stark and single secp256r1 sig fails
        await assert_execute_fails_with_signer(
            account,
            balanceof_call,
            stark_signer,
            'INVALID_SIG',
        )
        await assert_execute_fails_with_signer(
            account,
            balanceof_call,
            secp256r1_signer,
            'INVALID_SIG',
        )

        if webauthn_secp256r1_signer is None:
            account.signer = create_multisig_signer(stark_signer,
                                                    secp256r1_signer)
            await execute_calls(account, balanceof_call)
        else:
            await assert_execute_fails_with_signer(
                account,
                balanceof_call,
                webauthn_secp256r1_signer,
                'INVALID_SIG',
            )

            # stark + webauthn should fail
            stark_webauthn_multisg = create_multisig_signer(
                stark_signer, webauthn_secp256r1_signer)
            await assert_execute_fails_with_signer(
                account,
                balanceof_call,
                stark_webauthn_multisg,
                'INVALID_SIG',
            )

            # stark + hws should fail
            stark_hws_multisg = create_multisig_signer(stark_signer,
                                                       secp256r1_signer)
            await assert_execute_fails_with_signer(
                account,
                balanceof_call,
                stark_hws_multisg,
                'INVALID_SIG',
            )

            # hws + webauth multisig should work
            account.signer = create_multisig_signer(secp256r1_signer,
                                                    webauthn_secp256r1_signer)
            await execute_calls(account, balanceof_call)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "webauthn_secp256r1_keypair",
        "hws_secp256r1_keypair",
        "multisig_threshold",
    ],
    [
        (generate_secp256r1_keypair(), None, 0),
        (generate_secp256r1_keypair(), generate_secp256r1_keypair(), 0),
        (generate_secp256r1_keypair(), None, 2),
        (generate_secp256r1_keypair(), generate_secp256r1_keypair(), 2),
    ],
    ids=[
        "with_webauthn_no_multisig",
        "with_webauthn_and_hws_no_multisig",
        "with_webauthn_multisig",
        "with_webauthn_and_hws_multisig",
    ],
)
async def test_add_webauthn_signer(
    init_starknet,
    account_deployer,
    webauthn_secp256r1_keypair,
    hws_secp256r1_keypair,
    multisig_threshold,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    webauthn_secp256r1_pubk = flatten_seq(webauthn_secp256r1_keypair[1])
    hws_secp256r1_pubk = None if hws_secp256r1_keypair is None else flatten_seq(
        hws_secp256r1_keypair[1])
    account, _ = await account_deployer(stark_privk, hws_secp256r1_pubk, 0)
    account: Account

    stark_signer = create_stark_signer(stark_privk)
    legacy_stark_signer = create_legacy_stark_signer(stark_privk)
    hws_secp256r1_signer = None if hws_secp256r1_keypair is None else create_secp256r1_signer(
        hws_secp256r1_keypair[0])

    if hws_secp256r1_signer is not None:
        account.signer = hws_secp256r1_signer
    add_webauthn_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('add_secp256r1_signer'),
        calldata=[
            *webauthn_secp256r1_pubk, WEBAUTHN_SIGNER_TYPE, multisig_threshold
        ])
    exec_txn = await account.execute(
        calls=add_webauthn_call,
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    exec_txn_receipt = await devnet_client.get_transaction_receipt(
        exec_txn.transaction_hash)
    assert txn_receipt_contains_event(
        exec_txn_receipt,
        [
            get_selector_from_name("OwnerAdded"),
            poseidon_hash_many(webauthn_secp256r1_pubk),
        ],
        [WEBAUTHN_SIGNER_TYPE],
        match_data=True,
    ) is True, "no webauthn secp256r1 signer added event emitted"

    await is_account_signer(account,
                            poseidon_hash_many(webauthn_secp256r1_pubk))

    # stark signer can't sign a generic txn
    balanceof_call = Call(
        to_addr=int(FEE_CONTRACT_ADDRESS, 16),
        selector=get_selector_from_name('balanceOf'),
        calldata=[account.address],
    )
    await assert_execute_fails_with_signer(
        account,
        balanceof_call,
        stark_signer,
        'INVALID_SIG',
    )

    # legacy stark signer can't sign a generic txn
    await assert_execute_fails_with_signer(
        account,
        balanceof_call,
        legacy_stark_signer,
        'INVALID_SIG',
    )

    webauthn_secp256r1_signer = create_webauthn_signer(
        webauthn_secp256r1_keypair[0])
    if multisig_threshold == 0:
        # webauthn signer should work
        account.signer = webauthn_secp256r1_signer
        await execute_calls(account, balanceof_call)

        account.signer = create_webauthn_signer(webauthn_secp256r1_keypair[0],
                                                force_cairo_impl=True)
        await execute_calls(account, balanceof_call)

        if hws_secp256r1_signer is not None:
            # hws signer should also work in this case
            account.signer = hws_secp256r1_signer
            await execute_calls(account, balanceof_call)
    elif multisig_threshold == 2:
        # Check that both stark and single secp256r1 sig fails
        await assert_execute_fails_with_signer(
            account,
            balanceof_call,
            stark_signer,
            'INVALID_SIG',
        )
        await assert_execute_fails_with_signer(
            account,
            balanceof_call,
            webauthn_secp256r1_signer,
            'INVALID_SIG',
        )
        if hws_secp256r1_signer is None:
            account.signer = create_multisig_signer(stark_signer,
                                                    webauthn_secp256r1_signer)
            await execute_calls(account, balanceof_call)
        else:
            # single hws should fail
            await assert_execute_fails_with_signer(
                account,
                balanceof_call,
                hws_secp256r1_signer,
                'INVALID_SIG',
            )

            # stark + webauthn should fail
            stark_webauthn_multisg = create_multisig_signer(
                stark_signer, webauthn_secp256r1_signer)
            await assert_execute_fails_with_signer(
                account,
                balanceof_call,
                stark_webauthn_multisg,
                'INVALID_SIG',
            )

            # stark + hws should fail
            stark_hws_multisg = create_multisig_signer(stark_signer,
                                                       hws_secp256r1_signer)
            await assert_execute_fails_with_signer(
                account,
                balanceof_call,
                stark_hws_multisg,
                'INVALID_SIG',
            )

            # hws + webauth multisig should work
            account.signer = create_multisig_signer(hws_secp256r1_signer,
                                                    webauthn_secp256r1_signer)
            await execute_calls(account, balanceof_call)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "secp256r1_keypair",
        "webauthn_secp256r1_keypair",
        "multisig_threshold",
        "withdrawal_limit_low",
        "withdrawal_limit_high",
    ],
    [
        (generate_secp256r1_keypair(), None, 0, 0, 0),
        (generate_secp256r1_keypair(), None, 2, 0, 0),
        (generate_secp256r1_keypair(), generate_secp256r1_keypair(), 0, 0, 0),
        (generate_secp256r1_keypair(), generate_secp256r1_keypair(), 2, 0, 0),
        (generate_secp256r1_keypair(), None, 0, ETHER, 0),
        (generate_secp256r1_keypair(), None, 2, ETHER, 2 * ETHER),
        (generate_secp256r1_keypair(), generate_secp256r1_keypair(), 0, ETHER,
         0),
        (generate_secp256r1_keypair(), generate_secp256r1_keypair(), 2, ETHER,
         2 * ETHER),
    ],
    ids=[
        "with_secp256r1_no_multisig",
        "with_secp256r1_multisig",
        "with_secp256r1_no_multisig_with_webauthn",
        "with_secp256r1_multisig_with_webauthn",
        "with_secp256r1_no_multisig_with_thresh",
        "with_secp256r1_multisig_with_thresh",
        "with_secp256r1_no_multisig_with_webauthn_with_thresh",
        "with_secp256r1_multisig_with_webauthn_with_thresh",
    ],
)
async def test_remove_secp256r1_signer(
    init_starknet,
    account_deployer,
    init_pricing_contract,
    set_and_assert_low_threshold,
    set_and_assert_high_threshold,
    secp256r1_keypair,
    webauthn_secp256r1_keypair,
    multisig_threshold,
    withdrawal_limit_low,
    withdrawal_limit_high,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    webauthn_secp256r1_pubk = None if webauthn_secp256r1_keypair is None else flatten_seq(
        webauthn_secp256r1_keypair[1])
    account, _ = await account_deployer(stark_privk,
                                        webauthn_secp256r1_pubk,
                                        0,
                                        is_webauthn=True)
    account: Account
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    webauthn_secp256r1_signer = None if webauthn_secp256r1_keypair is None else create_webauthn_signer(
        webauthn_secp256r1_keypair[0])
    if webauthn_secp256r1_signer is not None:
        account.signer = webauthn_secp256r1_signer
    add_secp256r1_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('add_secp256r1_signer'),
        calldata=[*secp256r1_pubk, SECP256R1_SIGNER_TYPE, multisig_threshold])
    exec_txn = await account.execute(
        calls=add_secp256r1_call,
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    remove_secp256r1_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('remove_secp256r1_signer'),
        calldata=[
            poseidon_hash_many(secp256r1_pubk), SECP256R1_SIGNER_TYPE, 0
        ])

    stark_signer = create_stark_signer(stark_privk)
    secp256r1_signer = create_secp256r1_signer(secp256r1_keypair[0])
    if multisig_threshold == 0:
        account.signer = secp256r1_signer
    elif multisig_threshold == 2:
        account.signer = create_multisig_signer(
            stark_signer, secp256r1_signer
        ) if webauthn_secp256r1_signer is None else create_multisig_signer(
            secp256r1_signer, webauthn_secp256r1_signer)

    if withdrawal_limit_low > 0:
        await set_and_assert_low_threshold(withdrawal_limit_low, account)

    if withdrawal_limit_high > 0:
        await set_and_assert_high_threshold(withdrawal_limit_high, account)

    exec_txn = await account.execute(
        calls=remove_secp256r1_call,
        max_fee=int(0.1 * 10**18),
    )
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    assert txn_receipt_contains_event(
        res,
        [
            get_selector_from_name("OwnerRemoved"),
            poseidon_hash_many(secp256r1_pubk),
        ],
        [SECP256R1_SIGNER_TYPE],
        match_data=True,
    ) is True, "expected secp256r1 removed event emitted"
    assert txn_receipt_contains_event(
        res,
        [
            get_selector_from_name("DeferredRemoveSignerRequestCancelled"),
        ],
    ) is False, "did not expect a deferred req cancellation event"
    assert txn_receipt_contains_event(
        res,
        [get_selector_from_name("WithdrawalLimitHighSet")],
        [0],
        True,
    ) is (withdrawal_limit_high > 0), "withdrawal limit high not removed"
    assert txn_receipt_contains_event(
        res,
        [get_selector_from_name("WithdrawalLimitLowSet")],
        [0],
        True,
    ) is (withdrawal_limit_low > 0 and webauthn_secp256r1_signer
          is None), "withdrawal limit low not removed"

    account_signers = await devnet_client.call_contract(
        Call(
            to_addr=account.address,
            selector=get_selector_from_name("get_signers"),
            calldata=[],
        ))

    if webauthn_secp256r1_signer is None:
        assert account_signers == [
            1, KeyPair.from_private_key(stark_privk).public_key, 0, 0
        ], "No additional signers expected"
    else:
        assert account_signers == [
            1,
            KeyPair.from_private_key(stark_privk).public_key, 0, 1,
            poseidon_hash_many(webauthn_secp256r1_pubk)
        ], "No additional signers expected"

    account.signer = stark_signer if webauthn_secp256r1_signer is None else webauthn_secp256r1_signer
    balanceof_call = Call(
        to_addr=int(FEE_CONTRACT_ADDRESS, 16),
        selector=get_selector_from_name('balanceOf'),
        calldata=[account.address],
    )
    exec_txn = await account.execute(
        calls=balanceof_call,
        max_fee=int(0.1 * 10**18),
    )
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    assert res.execution_status == TransactionExecutionStatus.SUCCEEDED, "failed executing with stark signer"

    if webauthn_secp256r1_signer is None:
        account.signer = create_legacy_stark_signer(stark_privk)
        exec_txn = await account.execute(
            calls=balanceof_call,
            max_fee=int(0.1 * 10**18),
        )
        res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
        assert res.execution_status == TransactionExecutionStatus.SUCCEEDED, "failed executing with legacy stark signer"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "webauthn_secp256r1_keypair",
        "hws_secp256r1_keypair",
        "multisig_threshold",
    ],
    [
        (generate_secp256r1_keypair(), None, 0),
        (generate_secp256r1_keypair(), None, 2),
        (generate_secp256r1_keypair(), generate_secp256r1_keypair(), 0),
        (generate_secp256r1_keypair(), generate_secp256r1_keypair(), 2),
    ],
    ids=[
        "with_webauthn_no_multisig",
        "with_webauthn_multisig",
        "with_webauthn_no_multisig_with_hws",
        "with_webauthn_multisig_with_hws",
    ],
)
async def test_remove_webauthn_signer(
    init_starknet,
    account_deployer,
    init_pricing_contract,
    webauthn_secp256r1_keypair,
    hws_secp256r1_keypair,
    multisig_threshold,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    hws_secp256r1_pubk = None if hws_secp256r1_keypair is None else flatten_seq(
        hws_secp256r1_keypair[1])
    hws_secp256r1_signer = None if hws_secp256r1_keypair is None else create_secp256r1_signer(
        hws_secp256r1_keypair[0])
    account, _ = await account_deployer(stark_privk, hws_secp256r1_pubk, 0)
    account: Account
    webauthn_secp256r1_pubk = flatten_seq(webauthn_secp256r1_keypair[1])
    if hws_secp256r1_signer is not None:
        account.signer = hws_secp256r1_signer
    add_webauthn_secp256r1_keypair = Call(
        to_addr=account.address,
        selector=get_selector_from_name('add_secp256r1_signer'),
        calldata=[
            *webauthn_secp256r1_pubk, WEBAUTHN_SIGNER_TYPE, multisig_threshold
        ])
    exec_txn = await account.execute(
        calls=add_webauthn_secp256r1_keypair,
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    remove_webauthn_secp256r1_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('remove_secp256r1_signer'),
        calldata=[
            poseidon_hash_many(webauthn_secp256r1_pubk), WEBAUTHN_SIGNER_TYPE,
            0
        ],
    )

    stark_signer = create_stark_signer(stark_privk)
    webauthn_secp256r1_signer = create_webauthn_signer(
        webauthn_secp256r1_keypair[0])
    if multisig_threshold == 0:
        account.signer = webauthn_secp256r1_signer
    elif multisig_threshold == 2:
        account.signer = create_multisig_signer(
            stark_signer, webauthn_secp256r1_signer
        ) if hws_secp256r1_signer is None else create_multisig_signer(
            hws_secp256r1_signer, webauthn_secp256r1_signer)

    exec_txn = await account.execute(
        calls=remove_webauthn_secp256r1_call,
        max_fee=int(0.1 * 10**18),
    )
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    assert txn_receipt_contains_event(
        res,
        [
            get_selector_from_name("OwnerRemoved"),
            poseidon_hash_many(webauthn_secp256r1_pubk),
        ],
        [
            WEBAUTHN_SIGNER_TYPE,
        ],
        match_data=True,
    ) is True, "expected secp256r1 removed event emitted"
    assert txn_receipt_contains_event(
        res,
        [
            get_selector_from_name("DeferredRemoveSignerRequestCancelled"),
        ],
    ) is False, "did not expect a deferred req cancellation event"

    account_signers = await devnet_client.call_contract(
        Call(
            to_addr=account.address,
            selector=get_selector_from_name("get_signers"),
            calldata=[],
        ))
    if hws_secp256r1_keypair is None:
        assert account_signers == [
            1, KeyPair.from_private_key(stark_privk).public_key, 0, 0
        ], "No additional signers expected"
    else:
        assert account_signers == [
            1,
            KeyPair.from_private_key(stark_privk).public_key, 1,
            poseidon_hash_many(hws_secp256r1_pubk), 0
        ], "No additional signers expected"

    # verify existing signer can sign
    account.signer = stark_signer if hws_secp256r1_signer is None else hws_secp256r1_signer
    balanceof_call = Call(
        to_addr=int(FEE_CONTRACT_ADDRESS, 16),
        selector=get_selector_from_name('balanceOf'),
        calldata=[account.address],
    )
    exec_txn = await account.execute(
        calls=balanceof_call,
        max_fee=int(0.1 * 10**18),
    )
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    assert res.execution_status == TransactionExecutionStatus.SUCCEEDED, "failed executing with stark signer"

    if hws_secp256r1_signer is None:
        account.signer = create_legacy_stark_signer(stark_privk)
        exec_txn = await account.execute(
            calls=balanceof_call,
            max_fee=int(0.1 * 10**18),
        )
        res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
        assert res.execution_status == TransactionExecutionStatus.SUCCEEDED, "failed executing with legacy stark signer"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "secp256r1_keypair",
        "multisig_threshold",
    ],
    [
        (generate_secp256r1_keypair(), 0),
        (generate_secp256r1_keypair(), 2),
    ],
    ids=[
        "with_secp256r1_no_multisig",
        "with_secp256r1_multisig",
    ],
)
async def test_change_secp256r1_signer(
    init_starknet,
    account_deployer,
    secp256r1_keypair,
    multisig_threshold,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    add_secp256r1_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('add_secp256r1_signer'),
        calldata=[*secp256r1_pubk, SECP256R1_SIGNER_TYPE, multisig_threshold])
    exec_txn = await account.execute(
        calls=add_secp256r1_call,
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    curr_secp256r1_signer = create_secp256r1_signer(secp256r1_keypair[0])
    account.signer = curr_secp256r1_signer

    # Fail on invalid signer
    change_secp256r1_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('change_secp256r1_signer'),
        calldata=[[1234, 4321, 5678, 8765],
                  poseidon_hash_many(secp256r1_pubk), SECP256R1_SIGNER_TYPE],
    )
    with pytest.raises(Exception):
        exec_txn = await account.execute(
            calls=change_secp256r1_call,
            # max_fee=int(0.1 * 10**18),
            auto_estimate=True,
        )
        # await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    new_secp256r1_keypair = generate_secp256r1_keypair()
    new_secp256r1_pubk = flatten_seq(new_secp256r1_keypair[1])
    change_secp256r1_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('change_secp256r1_signer'),
        calldata=[
            *new_secp256r1_pubk,
            poseidon_hash_many(secp256r1_pubk), SECP256R1_SIGNER_TYPE
        ],
    )

    stark_signer = create_stark_signer(stark_privk)
    curr_multisig_signer = create_multisig_signer(stark_signer,
                                                  curr_secp256r1_signer)
    new_secp256r1_signer = create_secp256r1_signer(new_secp256r1_keypair[0])
    new_multisig_signer = create_multisig_signer(stark_signer,
                                                 new_secp256r1_signer)
    if multisig_threshold == 0:
        account.signer = curr_secp256r1_signer
    elif multisig_threshold == 2:
        account.signer = curr_multisig_signer
    exec_txn = await account.execute(
        calls=change_secp256r1_call,
        max_fee=int(0.1 * 10**18),
    )
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    assert txn_receipt_contains_event(
        res,
        [
            get_selector_from_name("OwnerAdded"),
            poseidon_hash_many(new_secp256r1_pubk),
        ],
        [
            SECP256R1_SIGNER_TYPE,
        ],
        match_data=True,
    ) is True, "no secp256r1 signer added event emitted"

    assert txn_receipt_contains_event(
        res,
        [
            get_selector_from_name("OwnerRemoved"),
            poseidon_hash_many(secp256r1_pubk),
        ],
        [
            SECP256R1_SIGNER_TYPE,
        ],
        match_data=True,
    ) is True, "no secp256r1 signer removed event emitted"

    await is_account_signer(account, poseidon_hash_many(new_secp256r1_pubk))

    balanceof_call = Call(
        to_addr=int(FEE_CONTRACT_ADDRESS, 16),
        selector=get_selector_from_name('balanceOf'),
        calldata=[account.address],
    )
    await assert_execute_fails_with_signer(account, balanceof_call,
                                           stark_signer, 'INVALID_SIG')
    if multisig_threshold == 0:
        await assert_execute_fails_with_signer(account, balanceof_call,
                                               curr_secp256r1_signer,
                                               'INVALID_SIG')
        account.signer = new_secp256r1_signer
    elif multisig_threshold == 2:
        await assert_execute_fails_with_signer(account, balanceof_call,
                                               curr_multisig_signer,
                                               'INVALID_SIG')
        account.signer = new_multisig_signer

    exec_txn = await account.execute(
        calls=balanceof_call,
        max_fee=int(0.1 * 10**18),
    )
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    assert res.execution_status == TransactionExecutionStatus.SUCCEEDED, "unexpected failed execution"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "secp256r1_keypair",
        "multisig_threshold",
    ],
    [
        (generate_secp256r1_keypair(), 0),
        (generate_secp256r1_keypair(), 2),
    ],
    ids=[
        "with_webauthn_no_multisig",
        "with_webauthn_multisig",
    ],
)
async def test_change_weauthn_signer(
    init_starknet,
    account_deployer,
    secp256r1_keypair,
    multisig_threshold,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account
    # account.signer = create_stark_signer(stark_privk)
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    add_weauthn_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('add_secp256r1_signer'),
        calldata=[*secp256r1_pubk, WEBAUTHN_SIGNER_TYPE, multisig_threshold])
    exec_txn = await account.execute(
        calls=add_weauthn_call,
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    await is_account_signer(account, poseidon_hash_many(secp256r1_pubk))

    curr_webauthn_signer = create_webauthn_signer(secp256r1_keypair[0])
    account.signer = curr_webauthn_signer

    # Fail on invalid signer
    change_weauthn_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('change_secp256r1_signer'),
        calldata=[[1234, 4321, 5678, 8765],
                  poseidon_hash_many(secp256r1_pubk), WEBAUTHN_SIGNER_TYPE],
    )
    with pytest.raises(Exception):
        exec_txn = await account.execute(
            calls=change_weauthn_call,
            # max_fee=int(0.1 * 10**18),
            auto_estimate=True,
        )
        # await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    new_secp256r1_keypair = generate_secp256r1_keypair()
    new_secp256r1_pubk = flatten_seq(new_secp256r1_keypair[1])
    change_webauthn_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('change_secp256r1_signer'),
        calldata=[
            *new_secp256r1_pubk,
            poseidon_hash_many(secp256r1_pubk), WEBAUTHN_SIGNER_TYPE
        ],
    )

    stark_signer = create_stark_signer(stark_privk)
    curr_multisig_signer = create_multisig_signer(stark_signer,
                                                  curr_webauthn_signer)
    new_weauthn_signer = create_webauthn_signer(new_secp256r1_keypair[0])
    new_multisig_signer = create_multisig_signer(stark_signer,
                                                 new_weauthn_signer)
    if multisig_threshold == 0:
        account.signer = curr_webauthn_signer
    elif multisig_threshold == 2:
        account.signer = curr_multisig_signer

    exec_txn = await account.execute(
        calls=change_webauthn_call,
        max_fee=int(0.1 * 10**18),
    )
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    assert txn_receipt_contains_event(
        res,
        [
            get_selector_from_name("OwnerAdded"),
            poseidon_hash_many(new_secp256r1_pubk),
        ],
        [
            WEBAUTHN_SIGNER_TYPE,
        ],
        match_data=True,
    ) is True, "no secp256r1 signer added event emitted"

    assert txn_receipt_contains_event(
        res,
        [
            get_selector_from_name("OwnerRemoved"),
            poseidon_hash_many(secp256r1_pubk),
        ],
        [
            WEBAUTHN_SIGNER_TYPE,
        ],
        match_data=True,
    ) is True, "no secp256r1 signer added event emitted"

    await is_account_signer(account, poseidon_hash_many(new_secp256r1_pubk))

    balanceof_call = Call(
        to_addr=int(FEE_CONTRACT_ADDRESS, 16),
        selector=get_selector_from_name('balanceOf'),
        calldata=[account.address],
    )
    await assert_execute_fails_with_signer(account, balanceof_call,
                                           stark_signer, 'INVALID_SIG')
    if multisig_threshold == 0:
        await assert_execute_fails_with_signer(account, balanceof_call,
                                               curr_webauthn_signer,
                                               'INVALID_SIG')
        account.signer = new_weauthn_signer
    elif multisig_threshold == 2:
        await assert_execute_fails_with_signer(account, balanceof_call,
                                               curr_multisig_signer,
                                               'INVALID_SIG')
        account.signer = new_multisig_signer

    exec_txn = await account.execute(
        calls=balanceof_call,
        max_fee=int(0.1 * 10**18),
    )
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    assert res.execution_status == TransactionExecutionStatus.SUCCEEDED, "unexpected failed execution"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "secp256r1_keypair",
        "multisig_threshold",
        "is_webauthn",
        "low_threshold",
        "custom_etd",
    ],
    [
        (generate_secp256r1_keypair(), 0, False, 0, 5 * 24 * 60 * 60),
        (generate_secp256r1_keypair(), 2, False, 0, None),
        (generate_secp256r1_keypair(), 0, True, 0, None),
        (generate_secp256r1_keypair(), 2, True, 0, None),
        (generate_secp256r1_keypair(), 0, False, ETHER, 5 * 24 * 60 * 60),
        (generate_secp256r1_keypair(), 2, False, ETHER, None),
        (generate_secp256r1_keypair(), 0, True, ETHER, None),
        (generate_secp256r1_keypair(), 2, True, ETHER, None),
    ],
    ids=[
        "with_secp256r1_no_multisig_custom_time_delay",
        "with_secp256r1_multisig",
        "with_webauthn_secp256r1_no_multisig",
        "with_webauthn_secp256r1_multisig",
        "with_secp256r1_no_multisig_with_thresh",
        "with_secp256r1_multisig_with_thresh",
        "with_webauthn_secp256r1_no_multisig_with_thresh",
        "with_webauthn_secp256r1_multisig_with_thresh",
    ],
)
async def test_deferred_remove_secp256r1_signer(
    init_starknet,
    account_deployer,
    init_pricing_contract,
    get_required_signer,
    set_and_assert_low_threshold,
    secp256r1_keypair,
    multisig_threshold,
    is_webauthn,
    low_threshold,
    custom_etd,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    signer_type = WEBAUTHN_SIGNER_TYPE if is_webauthn else SECP256R1_SIGNER_TYPE

    requests.post(f"{devnet_url}/set_time", json={"time": time.time()})

    account_etd = 24 * 4 * 60 * 60
    if custom_etd is not None:
        exec_txn = await account.execute(
            Call(
                to_addr=account.address,
                selector=get_selector_from_name("set_execution_time_delay"),
                calldata=[custom_etd],
            ),
            auto_estimate=True,
        )
        await devnet_client.wait_for_tx(exec_txn.transaction_hash)
        account_etd = (await devnet_client.call_contract(
            Call(
                to_addr=account.address,
                selector=get_selector_from_name("get_execution_time_delay"),
                calldata=[],
            )))[0]
        assert account_etd == custom_etd

    add_secp256r1_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('add_secp256r1_signer'),
        calldata=[*secp256r1_pubk, signer_type, multisig_threshold])
    exec_txn = await account.execute(
        calls=add_secp256r1_call,
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    secp256r1_signer = create_webauthn_signer(
        secp256r1_keypair[0]) if is_webauthn else create_secp256r1_signer(
            secp256r1_keypair[0])
    stark_signer = create_stark_signer(stark_privk)
    legacy_stark_signer = create_legacy_stark_signer(stark_privk)
    multisig_signer = create_multisig_signer(stark_signer, secp256r1_signer)
    account.signer = multisig_signer if multisig_threshold == 2 else secp256r1_signer
    if low_threshold > 0:
        await set_and_assert_low_threshold(ETHER, account)

    deferred_remove_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name("deferred_remove_signers"),
        calldata=[],
    )

    required_signer = await get_required_signer(
        account,
        call=deferred_remove_call,
    )
    assert required_signer == REQUIRED_SIGNER_STARK, 'stark signer can sign an etd request'
    required_signer = await get_required_signer(
        account,
        call=add_secp256r1_call,
    )
    assert required_signer == REQUIRED_SIGNER_MULTISIG if multisig_threshold == 2 else REQUIRED_SIGNER_STRONG, 'strong signer or multisig required for regular call'

    account.signer = stark_signer

    # Fail on invalid deferred removal call with calldata
    with pytest.raises(Exception, match="INVALID_ENTRYPOINT"):
        await account.execute(
            calls=Call(
                to_addr=deferred_remove_call.to_addr,
                selector=deferred_remove_call.selector,
                calldata=[31337, 31338],
            ),
            auto_estimate=True,
        )

    # Fail on high fees or paymaster
    with pytest.raises(Exception, match="INVALID_TX"):
        signed_txn = await account.sign_invoke_v3_transaction(
            calls=Call(
                to_addr=deferred_remove_call.to_addr,
                selector=deferred_remove_call.selector,
                calldata=[],
            ),
            l1_resource_bounds=ResourceBounds(
                max_amount=4000,
                max_price_per_unit=100000000000000000000 // 4000,
            ))
        # Current starknet.py doesn't support paymaster_data directly, so workaround..
        signed_txn.__dict__['paymaster_data'] = [0x2, 0x31337, 0x31338]
        sig_after_paymaster = account.signer.sign_transaction(signed_txn)
        signed_txn.__dict__['signature'] = sig_after_paymaster
        exec_txn = await devnet_client.send_transaction(signed_txn)
        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

        exec_txn = await account.execute_v3(
            calls=Call(
                to_addr=deferred_remove_call.to_addr,
                selector=deferred_remove_call.selector,
                calldata=[],
            ),
            l1_resource_bounds=ResourceBounds(
                max_amount=5001,
                max_price_per_unit=100000000000000000000 // 5000,
            ))
        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

        exec_txn = await account.execute(
            calls=Call(
                to_addr=deferred_remove_call.to_addr,
                selector=deferred_remove_call.selector,
                calldata=[],
            ),
            max_fee=15000000000000001,
        )
        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    exec_txn = await account.execute(
        calls=deferred_remove_call,
        auto_estimate=True,
        # max_fee=int(0.1 * 10**18),
    )
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    block = await devnet_client.get_block(block_number=res.block_number)
    block_timestamp = block.timestamp

    deferred_req = await devnet_client.call_contract(
        Call(
            to_addr=account.address,
            selector=get_selector_from_name("get_deferred_remove_signers"),
            calldata=[],
        ))
    # Some timing issue with devnet so we check an acceptable range
    expected_timestamp = block_timestamp + account_etd
    assert expected_timestamp - 30 <= deferred_req[0] <= expected_timestamp + 30

    # fail adding concurrent deferred removal
    with pytest.raises(Exception):
        exec_txn = await account.execute(
            calls=deferred_remove_call,
            auto_estimate=True,
            # max_fee=int(0.1 * 10**18),
        )

    # Fast forward but don't expire
    requests.post(f"{devnet_url}/increase_time",
                  json={"time": account_etd - 12 * 60 * 60})

    balanceof_call = Call(
        to_addr=int(FEE_CONTRACT_ADDRESS, 16),
        selector=get_selector_from_name('balanceOf'),
        calldata=[account.address],
    )

    # Fail as etd didn't expire yet
    with pytest.raises(Exception):
        account.signer = stark_signer
        exec_txn = await account.execute(
            calls=balanceof_call,
            auto_estimate=True,
            # max_fee=int(0.1 * 10**18),
        )
        # res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    # Actual signer (secp256r1 or multi) should still work
    if multisig_threshold == 0:
        account.signer = secp256r1_signer
    elif multisig_threshold == 2:
        account.signer = multisig_signer

    await execute_calls(account, balanceof_call)

    # Now expire
    requests.post(f"{devnet_url}/increase_time",
                  timeout=1000,
                  json={"time": 12 * 60 * 60 + 1})

    # Stark should work
    account.signer = stark_signer
    res = await execute_calls(account,
                              balanceof_call,
                              max_fee=int(0.1 * 10**18))
    assert txn_receipt_contains_event(
        res,
        [
            get_selector_from_name("OwnerRemoved"),
            poseidon_hash_many(secp256r1_pubk),
        ],
        [
            signer_type,
        ],
        match_data=True,
    ) is True, "no secp256r1 removed event emitted"
    assert txn_receipt_contains_event(
        res,
        [
            get_selector_from_name("DeferredRemoveSignerRequestExpired"),
        ],
    ) is True, "expected deferred req expiry event"

    # Legacy Stark should work
    account.signer = legacy_stark_signer
    exec_txn = await account.execute(
        calls=balanceof_call,
        max_fee=int(0.1 * 10**18),
    )
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    assert res.execution_status == TransactionExecutionStatus.SUCCEEDED, "unexpected failed execution"

    # Previous signer should fail
    with pytest.raises(Exception):
        if multisig_threshold == 0:
            account.signer = secp256r1_signer
        elif multisig_threshold == 2:
            account.signer = multisig_signer
        exec_txn = await account.execute(
            calls=balanceof_call,
            auto_estimate=True,
            # max_fee=int(0.1 * 10**18),
        )
        # res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "multisig_threshold",
    ],
    [
        (0, ),
        (2, ),
    ],
    ids=[
        "no_multisig",
        "multisig",
    ],
)
async def test_deferred_remove_all_signers(init_starknet, account_deployer,
                                           multisig_threshold):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account

    secp256r1_keypair = generate_secp256r1_keypair()
    webauthn_secp256r1_keypair = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    webauthn_secp256r1_pubk = flatten_seq(webauthn_secp256r1_keypair[1])

    deferred_remove_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name("deferred_remove_signers"),
        calldata=[],
    )

    # check that cannot add an etd without any strong signers
    # check just for non-multisig case, no need for redundant checks for other parameters
    if multisig_threshold == 0:
        with pytest.raises(Exception, match="INVALID_ENTRYPOINT"):
            await account.execute(calls=deferred_remove_call,
                                  auto_estimate=True)

    requests.post(f"{devnet_url}/set_time", json={"time": time.time()})

    add_secp256r1_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('add_secp256r1_signer'),
        calldata=[*secp256r1_pubk, SECP256R1_SIGNER_TYPE, multisig_threshold])

    add_webauthn_secp256r1_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('add_secp256r1_signer'),
        calldata=[
            *webauthn_secp256r1_pubk, WEBAUTHN_SIGNER_TYPE, multisig_threshold
        ])

    exec_txn = await account.execute(
        calls=[add_secp256r1_call, add_webauthn_secp256r1_call],
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    # secp256r1_signer = create_webauthn_signer(secp256r1_keypair[0]) if is_webauthn else create_secp256r1_signer(secp256r1_keypair[0])
    stark_signer = create_stark_signer(stark_privk)
    legacy_stark_signer = create_legacy_stark_signer(stark_privk)
    # multisig_signer = create_multisig_signer(stark_signer, secp256r1_signer)

    account.signer = stark_signer
    exec_txn = await account.execute(calls=deferred_remove_call,
                                     max_fee=10**16)
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    block = await devnet_client.get_block(block_number=res.block_number)
    block_timestamp = block.timestamp

    deferred_req = await devnet_client.call_contract(
        Call(
            to_addr=account.address,
            selector=get_selector_from_name("get_deferred_remove_signers"),
            calldata=[],
        ))
    # Some timing issue with devnet so we check an acceptable range
    expected_timestamp = block_timestamp + 4 * 24 * 60 * 60
    assert expected_timestamp - 30 <= deferred_req[0] <= expected_timestamp + 30

    # fail adding concurrent deferred removal
    with pytest.raises(Exception):
        exec_txn = await account.execute(
            calls=deferred_remove_call,
            auto_estimate=True,
            # max_fee=int(0.1 * 10**18),
        )

    balanceof_call = Call(
        to_addr=int(FEE_CONTRACT_ADDRESS, 16),
        selector=get_selector_from_name('balanceOf'),
        calldata=[account.address],
    )

    with pytest.raises(Exception):
        account.signer = stark_signer
        exec_txn = await account.execute(
            calls=balanceof_call,
            auto_estimate=True,
            # max_fee=int(0.1 * 10**18),
        )

    # Fast forward but don't expire
    requests.post(f"{devnet_url}/increase_time",
                  json={"time": int(3.5 * 24 * 60 * 60)})

    await is_account_signer(account, poseidon_hash_many(secp256r1_pubk))

    await is_account_signer(account,
                            poseidon_hash_many(webauthn_secp256r1_pubk))

    with pytest.raises(Exception):
        account.signer = stark_signer
        exec_txn = await account.execute(
            calls=balanceof_call,
            auto_estimate=True,
            # max_fee=int(0.1 * 10**18),
        )

    # Now expire
    requests.post(f"{devnet_url}/increase_time",
                  timeout=1000,
                  json={"time": int(4 * 24 * 60 * 60 + 1)})

    # Stark should work
    account.signer = stark_signer
    res = await execute_calls(account,
                              balanceof_call,
                              max_fee=int(0.1 * 10**18))
    assert txn_receipt_contains_event(
        res,
        [
            get_selector_from_name("OwnerRemoved"),
            poseidon_hash_many(secp256r1_pubk),
        ],
        [
            SECP256R1_SIGNER_TYPE,
        ],
        match_data=True,
    ) is True, "no secp256r1 removed event emitted"
    assert txn_receipt_contains_event(
        res,
        [
            get_selector_from_name("OwnerRemoved"),
            poseidon_hash_many(webauthn_secp256r1_pubk),
        ],
        [
            WEBAUTHN_SIGNER_TYPE,
        ],
        match_data=True,
    ) is True, "no secp256r1 removed event emitted"
    assert txn_receipt_contains_event(
        res,
        [
            get_selector_from_name("DeferredRemoveSignerRequestExpired"),
        ],
    ) is True, "expected deferred req expiry event"

    if multisig_threshold > 0:
        assert txn_receipt_contains_event(
            res,
            [
                get_selector_from_name("MultisigSet"),
            ],
            [0],
        ) is True, "expected multisig set to 0 event"

    # Legacy Stark should work
    account.signer = legacy_stark_signer
    exec_txn = await account.execute(
        calls=balanceof_call,
        max_fee=int(0.1 * 10**18),
    )
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    assert res.execution_status == TransactionExecutionStatus.SUCCEEDED, "unexpected failed execution"

    # Now re-add some strong signer and verify it works
    await execute_calls(
        account,
        Call(to_addr=account.address,
             selector=get_selector_from_name('add_secp256r1_signer'),
             calldata=[*secp256r1_pubk, SECP256R1_SIGNER_TYPE, 0]))

    account.signer = create_secp256r1_signer(secp256r1_keypair[0])

    await execute_calls(account, balanceof_call)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "secp256r1_keypair",
        "multisig_threshold",
        "is_webauthn",
    ],
    [
        (generate_secp256r1_keypair(), 0, False),
        (generate_secp256r1_keypair(), 2, False),
        (generate_secp256r1_keypair(), 0, True),
        (generate_secp256r1_keypair(), 2, True),
    ],
    ids=[
        "with_secp256r1_no_multisig",
        "with_secp256r1_multisig",
        "with_webauthn_secp256r1_no_multisig",
        "with_webauthn_secp256r1_multisig",
    ],
)
async def test_cancel_deferred_remove_secp256r1_signer(
    init_starknet,
    account_deployer,
    secp256r1_keypair,
    multisig_threshold,
    is_webauthn,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    legacy_stark_signer = create_legacy_stark_signer(stark_privk)
    signer_type = WEBAUTHN_SIGNER_TYPE if is_webauthn else SECP256R1_SIGNER_TYPE

    requests.post(f"{devnet_url}/set_time", json={"time": time.time()})

    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    add_secp256r1_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('add_secp256r1_signer'),
        calldata=[*secp256r1_pubk, signer_type, multisig_threshold])
    exec_txn = await account.execute(
        calls=add_secp256r1_call,
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    secp256r1_signer = create_webauthn_signer(
        secp256r1_keypair[0]) if is_webauthn else create_secp256r1_signer(
            secp256r1_keypair[0])
    stark_signer = create_stark_signer(stark_privk)
    multisig_signer = create_multisig_signer(stark_signer, secp256r1_signer)

    account.signer = stark_signer
    deferred_remove_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name("deferred_remove_signers"),
        calldata=[],
    )
    exec_txn = await account.execute(calls=deferred_remove_call,
                                     max_fee=10**16)
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    assert txn_receipt_contains_event(
        res,
        [
            get_selector_from_name("DeferredRemoveSignerRequest"),
        ],
    ) is True, "expected deferred req event"

    # Remove the signer should cancel the deferred req
    remove_secp256r1_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('remove_secp256r1_signer'),
        calldata=[poseidon_hash_many(secp256r1_pubk), signer_type, 0],
    )

    if multisig_threshold == 0:
        account.signer = secp256r1_signer
    elif multisig_threshold == 2:
        account.signer = multisig_signer

    exec_txn = await account.execute(
        calls=remove_secp256r1_call,
        max_fee=int(0.1 * 10**18),
    )
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    assert txn_receipt_contains_event(
        res,
        [
            get_selector_from_name("DeferredRemoveSignerRequestCancelled"),
        ],
    ) is True, "expected a deferred req cancellation event"
    deferred_req = await devnet_client.call_contract(
        Call(
            to_addr=account.address,
            selector=get_selector_from_name("get_deferred_remove_signers"),
            calldata=[],
        ))
    assert deferred_req[
        0] == 0, "expected empty deferred remove secp256r1 signer"

    # Re-add the signer and cancel the deferred req directly
    account.signer = stark_signer
    exec_txn = await account.execute(
        calls=add_secp256r1_call,
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    exec_txn = await account.execute(calls=deferred_remove_call,
                                     max_fee=10**16)
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    cancel_deferred_remove_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name("cancel_deferred_remove_signers"),
        calldata=[],
    )

    # Stark signer cannot cancel
    with pytest.raises(Exception):
        exec_txn = await account.execute(
            calls=cancel_deferred_remove_call,
            auto_estimate=True,
            # max_fee=int(0.1 * 10**18),
        )
        # res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    # But actual account signer can
    if multisig_threshold == 0:
        account.signer = secp256r1_signer
    elif multisig_threshold == 2:
        account.signer = multisig_signer
    exec_txn = await account.execute(
        calls=cancel_deferred_remove_call,
        max_fee=int(0.1 * 10**18),
    )
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    assert txn_receipt_contains_event(
        res,
        [get_selector_from_name("DeferredRemoveSignerRequestCancelled")],
    ) is True, "expected deferred req cancellation event"
    deferred_req = await devnet_client.call_contract(
        Call(
            to_addr=account.address,
            selector=get_selector_from_name("get_deferred_remove_signers"),
            calldata=[],
        ))
    assert deferred_req[
        0] == 0, "expected empty deferred remove secp256r1 signer"

    # "Expire request"
    requests.post(f"{devnet_url}/increase_time",
                  timeout=1000,
                  json={"time": 4 * 24 * 60 * 60 + 1})

    balanceof_call = Call(
        to_addr=int(FEE_CONTRACT_ADDRESS, 16),
        selector=get_selector_from_name('balanceOf'),
        calldata=[account.address],
    )
    # Stark signer can't sign as deferred remove req should never have happened
    with pytest.raises(Exception):
        account.signer = stark_signer
        exec_txn = await account.execute(
            calls=balanceof_call,
            auto_estimate=True,
            # max_fee=int(0.1 * 10**18),
        )

        account.signer = legacy_stark_signer
        exec_txn = await account.execute(
            calls=balanceof_call,
            auto_estimate=True,
            # max_fee=int(0.1 * 10**18),
        )
        # res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)


@pytest.mark.asyncio
async def test_set_execution_time_delay(
    init_starknet,
    account_deployer,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)

    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account

    # Fail on less than min etd
    with pytest.raises(Exception):
        exec_txn = await account.execute(
            Call(
                to_addr=account.address,
                selector=get_selector_from_name("set_execution_time_delay"),
                calldata=[24 * 60 * 60 - 1],
            ),
            auto_estimate=True,
        )

    # Fail on more than max etd
    with pytest.raises(Exception):
        exec_txn = await account.execute(
            Call(
                to_addr=account.address,
                selector=get_selector_from_name("set_execution_time_delay"),
                calldata=[365 * 24 * 60 * 60 + 1],
            ),
            auto_estimate=True,
        )

    # Set a valid etd
    custom_etd = 365 * 24 * 60 * 60 - 1
    exec_txn = await account.execute(
        Call(
            to_addr=account.address,
            selector=get_selector_from_name("set_execution_time_delay"),
            calldata=[custom_etd],
        ),
        auto_estimate=True,
    )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    account_etd = (await devnet_client.call_contract(
        Call(
            to_addr=account.address,
            selector=get_selector_from_name("get_execution_time_delay"),
            calldata=[],
        )))[0]
    assert account_etd == custom_etd


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "secp256r1_keypair1",
        "secp256r1_keypair2",
        "secp256r1_type",
        "multisig_threshold",
    ],
    [
        (generate_secp256r1_keypair(), generate_secp256r1_keypair(),
         SECP256R1_SIGNER_TYPE, 0),
        (generate_secp256r1_keypair(), generate_secp256r1_keypair(),
         SECP256R1_SIGNER_TYPE, 2),
        (generate_secp256r1_keypair(), generate_secp256r1_keypair(),
         WEBAUTHN_SIGNER_TYPE, 0),
        (generate_secp256r1_keypair(), generate_secp256r1_keypair(),
         WEBAUTHN_SIGNER_TYPE, 2),
    ],
    ids=[
        "with_secp256r1_no_multisig",
        "with_secp256r1_multisig",
        "with_webauthn_secp256r1_no_multisig",
        "with_webauthn_secp256r1_multisig",
    ],
)
async def test_multiple_secp256r1_signers(
    init_starknet,
    account_deployer,
    secp256r1_keypair1,
    secp256r1_keypair2,
    secp256r1_type,
    multisig_threshold,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk)
    legacy_stark_signer = create_legacy_stark_signer(stark_privk)
    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account
    secp256r1_pubk1 = flatten_seq(secp256r1_keypair1[1])
    add_secp256r1_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('add_secp256r1_signer'),
        calldata=[*secp256r1_pubk1, secp256r1_type, multisig_threshold])
    exec_txn = await account.execute(
        calls=add_secp256r1_call,
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    secp256r1_signer1 = create_secp256r1_signer(
        secp256r1_keypair1[0]
    ) if secp256r1_type == SECP256R1_SIGNER_TYPE else create_webauthn_signer(
        secp256r1_keypair1[0])
    multi_sig_signer1 = create_multisig_signer(stark_signer, secp256r1_signer1)

    # adding second hw signer
    secp256r1_pubk2 = flatten_seq(secp256r1_keypair2[1])
    if multisig_threshold == 0:
        account.signer = secp256r1_signer1
    elif multisig_threshold == 2:
        account.signer = multi_sig_signer1
    add_secp256r1_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('add_secp256r1_signer'),
        calldata=[*secp256r1_pubk2, secp256r1_type, multisig_threshold])
    exec_txn = await account.execute(
        calls=add_secp256r1_call,
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    balanceof_call = Call(
        to_addr=int(FEE_CONTRACT_ADDRESS, 16),
        selector=get_selector_from_name('balanceOf'),
        calldata=[account.address],
    )
    await assert_execute_fails_with_signer(account, balanceof_call,
                                           stark_signer, 'INVALID_SIG')
    await assert_execute_fails_with_signer(account, balanceof_call,
                                           legacy_stark_signer, 'INVALID_SIG')

    # send out txs with both signers and see they work
    if multisig_threshold == 0:
        account.signer = secp256r1_signer1
    elif multisig_threshold == 2:
        account.signer = multi_sig_signer1

    exec_txn = await account.execute(
        calls=balanceof_call,
        max_fee=int(0.1 * 10**18),
    )
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    assert res.execution_status == TransactionExecutionStatus.SUCCEEDED, "failed executing with stark signer 1"

    secp256r1_signer2 = create_secp256r1_signer(
        secp256r1_keypair2[0]
    ) if secp256r1_type == SECP256R1_SIGNER_TYPE else create_webauthn_signer(
        secp256r1_keypair2[0])
    multi_sig_signer2 = create_multisig_signer(stark_signer, secp256r1_signer2)
    if multisig_threshold == 0:
        account.signer = secp256r1_signer2
    elif multisig_threshold == 2:
        account.signer = multi_sig_signer2

    exec_txn = await account.execute(
        calls=balanceof_call,
        max_fee=int(0.1 * 10**18),
    )
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    assert res.execution_status == TransactionExecutionStatus.SUCCEEDED, "failed executing with stark signer 2"

    # see everything works when doing deferred removal


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "secp256r1_keypair",
        "multisig_threshold",
        "move_secp256r1_idx",
    ],
    [
        (None, 0, False),
        (generate_secp256r1_keypair(), 0, False),
        (generate_secp256r1_keypair(), 0, True),
        (generate_secp256r1_keypair(), 2, False),
    ],
    ids=[
        "basic_stark",
        "with_secp256r1_no_multisig",
        "with_secp256r1_no_multisig_move_idx",
        "with_secp256r1_multisig",
    ],
)
async def test_regenesis_upgrade(
    init_starknet,
    account_declare,
    account_deployer,
    secp256r1_keypair,
    multisig_threshold,
    move_secp256r1_idx,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    devnet_account: Account
    account_chash, _, account_cairo0_chash, proxy_cairo0_chash = account_declare
    stark_privk = random.randint(1, 10**10)
    stark_keypair = KeyPair.from_private_key(stark_privk)
    stark_pubk = stark_keypair.public_key
    ctor_calldata = [
        account_cairo0_chash,
        get_selector_from_name("initializer"), 1, stark_pubk
    ]
    secp256r1_pubk = [*flatten_seq(secp256r1_keypair[1]), 2, 0, 0
                      ] if secp256r1_keypair is not None else [0] * 7
    account_address = compute_address(
        class_hash=proxy_cairo0_chash,
        salt=stark_pubk,
        constructor_calldata=ctor_calldata,
    )
    exec = await devnet_account.execute(
        Call(
            to_addr=int(FEE_CONTRACT_ADDRESS, 16),
            selector=get_selector_from_name("transfer"),
            calldata=[
                account_address,
                3 * 10**18,
                0,
            ],
        ),
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec.transaction_hash)

    deploy_signer = namedtuple(
        "_DeploySigner",
        ["sign_transaction"])(lambda depl_account: cairo0_deployment_signer(
            depl_account, account_address, stark_keypair, account_cairo0_chash,
            secp256r1_pubk))
    deployer_account = Account(
        client=devnet_client,
        address=account_address,
        signer=deploy_signer,
    )
    signed_account_depl = await deployer_account.sign_deploy_account_v1_transaction(
        class_hash=proxy_cairo0_chash,
        contract_address_salt=stark_pubk,
        constructor_calldata=ctor_calldata,
        auto_estimate=True,
    )
    account_depl = await devnet_client.deploy_account(signed_account_depl)
    receipt = await devnet_client.wait_for_tx(account_depl.transaction_hash)
    assert receipt.execution_status == TransactionExecutionStatus.SUCCEEDED
    stark_signer = create_legacy_stark_signer(stark_privk)
    account = Account(
        client=devnet_client,
        address=account_address,
        signer=stark_signer,
        chain=StarknetChainId.TESTNET,
    )
    await account.cairo_version
    secp256r1_signer = create_secp256r1_signer(
        secp256r1_keypair[0],
        legacy=True) if secp256r1_keypair is not None else None
    if secp256r1_keypair is not None:
        secp256r1_signer_wrapper = namedtuple(
            "SignerWrapper", "sign_transaction")(
                lambda txn: [1, *secp256r1_signer.sign_transaction(txn)])
        # we already have secp256r1 signer from deployment - del and re-add so won't be in index 1
        account.signer = secp256r1_signer_wrapper
        if move_secp256r1_idx is True:
            for i in range(1, 3):
                await execute_calls(
                    account,
                    Call(to_addr=account_address,
                         selector=get_selector_from_name("remove_signer"),
                         calldata=[i]),
                )
                account.signer = stark_signer
                await execute_calls(
                    account,
                    Call(to_addr=account_address,
                         selector=get_selector_from_name("add_signer"),
                         calldata=secp256r1_pubk),
                )
                signer_id = i + 1
                secp256r1_signer_wrapper = namedtuple(
                    "SignerWrapper", "sign_transaction")(
                        lambda txn:
                        [signer_id, *secp256r1_signer.sign_transaction(txn)])
                account.signer = secp256r1_signer_wrapper
    if multisig_threshold == 2:
        await execute_calls(
            account,
            Call(to_addr=account.address,
                 selector=get_selector_from_name("set_multisig"),
                 calldata=[2]),
        )
        stark_signer_wrapper = namedtuple(
            "StarkSignerWrapper", "sign_transaction")(
                lambda txn: [0, *stark_signer.sign_transaction(txn)])
        account.signer = create_multisig_signer(stark_signer_wrapper,
                                                secp256r1_signer_wrapper)

    await execute_calls(
        account,
        Call(
            to_addr=account.address,
            selector=get_selector_from_name("upgrade_regenesis"),
            calldata=[
                account_chash,
                0x2ceccef7f994940b3962a6c67e0ba4fcd37df7d131417c604f91e03caecc1cd
            ],
        ),
    )

    upgraded_chash = await devnet_client.get_class_hash_at(account.address)
    assert upgraded_chash == account_chash, "replace_class failure"

    stark_pubkey_call_res = await devnet_client.call_contract(
        Call(
            to_addr=account.address,
            selector=get_selector_from_name("get_public_key"),
            calldata=[],
        ))
    assert stark_pubkey_call_res[
        0] == stark_pubk, "stark public key was not migrated"

    account = Account(
        client=devnet_client,
        address=account.address,
        key_pair=stark_keypair,
        chain=StarknetChainId.TESTNET,
    )
    await account.cairo_version
    # at this point we are already in new Account signature format so recreate signer helpers
    stark_signer = create_stark_signer(stark_privk)
    if secp256r1_keypair is not None:
        secp256r1_signer = create_secp256r1_signer(secp256r1_keypair[0],
                                                   legacy=False)
        await is_account_signer(
            account, poseidon_hash_many(flatten_seq(secp256r1_keypair[1])))

        account.signer = secp256r1_signer
        if multisig_threshold == 2:
            account.signer = create_multisig_signer(stark_signer,
                                                    secp256r1_signer)
            multisig_thresh_call_res = await devnet_client.call_contract(
                Call(
                    to_addr=account.address,
                    selector=get_selector_from_name("get_multisig_threshold"),
                    calldata=[],
                ))
            assert multisig_thresh_call_res[
                0] == multisig_threshold, "multisig threshold was not migrated"
    else:
        account.signer = stark_signer
    await execute_calls(
        account,
        Call(to_addr=int(FEE_CONTRACT_ADDRESS, 16),
             selector=get_selector_from_name("balanceOf"),
             calldata=[account.address]),
    )

    # Fail on regenesis storage migration re-entry
    with pytest.raises(Exception):
        await execute_calls(
            account,
            Call(to_addr=account.address,
                 selector=get_selector_from_name('migrate_storage'),
                 calldata=[int.from_bytes(b'000.000.011', 'big')]),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "secp256r1_keypair1",
        "secp256r1_keypair2",
        "secp256r1_type",
        "multisig_threshold",
    ],
    [
        (generate_secp256r1_keypair(), generate_secp256r1_keypair(),
         SECP256R1_SIGNER_TYPE, 0),
        (generate_secp256r1_keypair(), generate_secp256r1_keypair(),
         SECP256R1_SIGNER_TYPE, 0),
        (generate_secp256r1_keypair(), generate_secp256r1_keypair(),
         WEBAUTHN_SIGNER_TYPE, 2),
        (generate_secp256r1_keypair(), generate_secp256r1_keypair(),
         WEBAUTHN_SIGNER_TYPE, 2),
    ],
    ids=[
        "with_secp256r1_no_multisig",
        "with_secp256r1_multisig",
        "with_webauthn_secp256r1_no_multisig",
        "with_webauthn_secp256r1_multisig",
    ],
)
async def test_multiple_secp256r1_signers_with_signer_change(
    init_starknet,
    account_deployer,
    secp256r1_keypair1,
    secp256r1_keypair2,
    secp256r1_type,
    multisig_threshold,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk)
    _ = create_legacy_stark_signer(stark_privk)
    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account
    secp256r1_pubk1 = flatten_seq(secp256r1_keypair1[1])
    add_secp256r1_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('add_secp256r1_signer'),
        calldata=[*secp256r1_pubk1, secp256r1_type, multisig_threshold])
    exec_txn = await account.execute(
        calls=add_secp256r1_call,
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    secp256r1_signer1 = create_secp256r1_signer(
        secp256r1_keypair1[0]
    ) if secp256r1_type == SECP256R1_SIGNER_TYPE else create_webauthn_signer(
        secp256r1_keypair1[0])
    multi_sig_signer1 = create_multisig_signer(stark_signer, secp256r1_signer1)

    # adding second hw signer
    secp256r1_pubk2 = flatten_seq(secp256r1_keypair2[1])
    if multisig_threshold == 0:
        account.signer = secp256r1_signer1
    elif multisig_threshold == 2:
        account.signer = multi_sig_signer1
    add_secp256r1_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('add_secp256r1_signer'),
        calldata=[*secp256r1_pubk2, secp256r1_type, multisig_threshold])
    exec_txn = await account.execute(
        calls=add_secp256r1_call,
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    secp256r1_signer2 = create_secp256r1_signer(
        secp256r1_keypair2[0]
    ) if secp256r1_type == SECP256R1_SIGNER_TYPE else create_webauthn_signer(
        secp256r1_keypair2[0])
    multi_sig_signer2 = create_multisig_signer(stark_signer, secp256r1_signer2)

    # change and see it all still works
    if multisig_threshold == 0:
        account.signer = secp256r1_signer1
    elif multisig_threshold == 2:
        account.signer = multi_sig_signer1

    new_secp256r1_keypair = generate_secp256r1_keypair()
    new_secp256r1_pubk = flatten_seq(new_secp256r1_keypair[1])
    new_secp256r1_signer = create_secp256r1_signer(
        new_secp256r1_keypair[0]
    ) if secp256r1_type == SECP256R1_SIGNER_TYPE else create_webauthn_signer(
        new_secp256r1_keypair[0])
    new_multisig_signer = create_multisig_signer(stark_signer,
                                                 new_secp256r1_signer)
    change_secp256r1_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('change_secp256r1_signer'),
        calldata=[
            *new_secp256r1_pubk,
            poseidon_hash_many(secp256r1_pubk1), secp256r1_type
        ],
    )

    exec_txn = await account.execute(
        calls=change_secp256r1_call,
        max_fee=int(0.1 * 10**18),
    )
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    assert txn_receipt_contains_event(
        res,
        [
            get_selector_from_name("OwnerAdded"),
            poseidon_hash_many(new_secp256r1_pubk),
        ],
        [
            secp256r1_type,
        ],
        match_data=True,
    ) is True, "no secp256r1 signer added event emitted"

    assert txn_receipt_contains_event(
        res,
        [
            get_selector_from_name("OwnerRemoved"),
            poseidon_hash_many(secp256r1_pubk1),
        ],
        [secp256r1_type],
        match_data=True,
    ) is True, "no secp256r1 signer added event emitted"

    # make sure other signers removed after change
    balanceof_call = Call(
        to_addr=int(FEE_CONTRACT_ADDRESS, 16),
        selector=get_selector_from_name('balanceOf'),
        calldata=[account.address],
    )

    if multisig_threshold == 0:
        await assert_execute_fails_with_signer(account, balanceof_call,
                                               secp256r1_signer1,
                                               'INVALID_SIG')
        account.signer = secp256r1_signer2
        exec_txn = await account.execute(
            calls=balanceof_call,
            max_fee=int(0.1 * 10**18),
        )
        res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    elif multisig_threshold == 2:
        await assert_execute_fails_with_signer(account, balanceof_call,
                                               multi_sig_signer1,
                                               'INVALID_SIG')
        account.signer = multi_sig_signer2
        exec_txn = await account.execute(
            calls=balanceof_call,
            max_fee=int(0.1 * 10**18),
        )
        res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
        assert res.execution_status == TransactionExecutionStatus.SUCCEEDED, "failed executing with stark signer 2"

    if multisig_threshold == 0:
        account.signer = new_secp256r1_signer
    elif multisig_threshold == 2:
        account.signer = new_multisig_signer

    exec_txn = await account.execute(
        calls=balanceof_call,
        max_fee=int(0.1 * 10**18),
    )
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    assert res.execution_status == TransactionExecutionStatus.SUCCEEDED, "failed executing with stark signer 2"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "secp256r1_keypair1",
        "secp256r1_keypair2",
        "webauthn_secp256r1_keypair1",
        "webauthn_secp256r1_keypair2",
        "multisig_threshold",
    ],
    [
        (generate_secp256r1_keypair(), generate_secp256r1_keypair(),
         generate_secp256r1_keypair(), generate_secp256r1_keypair(), 2),
        (generate_secp256r1_keypair(), generate_secp256r1_keypair(),
         generate_secp256r1_keypair(), generate_secp256r1_keypair(), 0),
    ],
    ids=[
        "multisig",
        "no_multisig",
    ],
)
async def test_multiple_hws_and_webauthn_signers_with_signer_change(
    init_starknet,
    account_deployer,
    secp256r1_keypair1,
    secp256r1_keypair2,
    webauthn_secp256r1_keypair1,
    webauthn_secp256r1_keypair2,
    multisig_threshold,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk)

    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account

    secp256r1_pubk1 = flatten_seq(secp256r1_keypair1[1])
    secp256r1_pubk2 = flatten_seq(secp256r1_keypair2[1])
    webauthn_secp256r1_pubk1 = flatten_seq(webauthn_secp256r1_keypair1[1])
    webauthn_secp256r1_pubk2 = flatten_seq(webauthn_secp256r1_keypair2[1])

    secp256r1_signer1 = create_secp256r1_signer(secp256r1_keypair1[0])
    secp256r1_signer2 = create_secp256r1_signer(secp256r1_keypair2[0])
    webauthn_secp256r1_signer1 = create_webauthn_signer(
        webauthn_secp256r1_keypair1[0])
    webauthn_secp256r1_signer2 = create_webauthn_signer(
        webauthn_secp256r1_keypair2[0])

    add_secp256r1_call1 = Call(
        to_addr=account.address,
        selector=get_selector_from_name('add_secp256r1_signer'),
        calldata=[*secp256r1_pubk1, SECP256R1_SIGNER_TYPE, multisig_threshold])
    add_secp256r1_call2 = Call(
        to_addr=account.address,
        selector=get_selector_from_name('add_secp256r1_signer'),
        calldata=[*secp256r1_pubk2, SECP256R1_SIGNER_TYPE, multisig_threshold])
    add_webauthn_secp256r1_call1 = Call(
        to_addr=account.address,
        selector=get_selector_from_name('add_secp256r1_signer'),
        calldata=[
            *webauthn_secp256r1_pubk1, WEBAUTHN_SIGNER_TYPE, multisig_threshold
        ])
    add_webauthn_secp256r1_call2 = Call(
        to_addr=account.address,
        selector=get_selector_from_name('add_secp256r1_signer'),
        calldata=[
            *webauthn_secp256r1_pubk2, WEBAUTHN_SIGNER_TYPE, multisig_threshold
        ])
    exec_txn = await account.execute(
        calls=[
            add_secp256r1_call1, add_secp256r1_call2,
            add_webauthn_secp256r1_call1, add_webauthn_secp256r1_call2
        ],
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    balanceof_call = Call(
        to_addr=int(FEE_CONTRACT_ADDRESS, 16),
        selector=get_selector_from_name('balanceOf'),
        calldata=[account.address],
    )

    await assert_execute_fails_with_signer(account, balanceof_call,
                                           stark_signer, 'INVALID_SIG')

    if multisig_threshold == 0:
        account.signer = secp256r1_signer1
        await execute_calls(account, balanceof_call)
        account.signer = secp256r1_signer2
        await execute_calls(account, balanceof_call)
        account.signer = webauthn_secp256r1_signer1
        await execute_calls(account, balanceof_call)
        account.signer = webauthn_secp256r1_signer2
        await execute_calls(account, balanceof_call)
    if multisig_threshold == 2:
        await assert_execute_fails_with_signer(account, balanceof_call,
                                               secp256r1_signer1,
                                               'INVALID_SIG')
        await assert_execute_fails_with_signer(account, balanceof_call,
                                               secp256r1_signer2,
                                               'INVALID_SIG')
        await assert_execute_fails_with_signer(account, balanceof_call,
                                               webauthn_secp256r1_signer1,
                                               'INVALID_SIG')
        await assert_execute_fails_with_signer(account, balanceof_call,
                                               webauthn_secp256r1_signer2,
                                               'INVALID_SIG')

        # when webauthn and hws are both present, multisig is only valid when both are present
        await assert_execute_fails_with_signer(
            account, balanceof_call,
            create_multisig_signer(stark_signer, secp256r1_signer1),
            'INVALID_SIG')
        await assert_execute_fails_with_signer(
            account, balanceof_call,
            create_multisig_signer(stark_signer, secp256r1_signer2),
            'INVALID_SIG')
        await assert_execute_fails_with_signer(
            account, balanceof_call,
            create_multisig_signer(stark_signer, webauthn_secp256r1_signer1),
            'INVALID_SIG')
        await assert_execute_fails_with_signer(
            account, balanceof_call,
            create_multisig_signer(stark_signer, webauthn_secp256r1_signer2),
            'INVALID_SIG')

        await assert_execute_fails_with_signer(
            account, balanceof_call,
            create_multisig_signer(secp256r1_signer1, secp256r1_signer2),
            'INVALID_SIG')
        await assert_execute_fails_with_signer(
            account, balanceof_call,
            create_multisig_signer(webauthn_secp256r1_signer1,
                                   webauthn_secp256r1_signer2), 'INVALID_SIG')

        account.signer = create_multisig_signer(secp256r1_signer1,
                                                webauthn_secp256r1_signer1)
        await execute_calls(account, balanceof_call)
        account.signer = create_multisig_signer(secp256r1_signer1,
                                                webauthn_secp256r1_signer2)
        await execute_calls(account, balanceof_call)
        account.signer = create_multisig_signer(secp256r1_signer2,
                                                webauthn_secp256r1_signer1)
        await execute_calls(account, balanceof_call)
        account.signer = create_multisig_signer(secp256r1_signer2,
                                                webauthn_secp256r1_signer2)
        await execute_calls(account, balanceof_call)

    new_secp256r1_keypair = generate_secp256r1_keypair()
    new_webauthn_secp256r1_keypair = generate_secp256r1_keypair()
    new_secp256r1_signer = create_secp256r1_signer(new_secp256r1_keypair[0])
    new_webauthn_secp256r1_signer = create_webauthn_signer(
        new_webauthn_secp256r1_keypair[0])

    change_secp256r1_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('change_secp256r1_signer'),
        calldata=[
            *flatten_seq(new_secp256r1_keypair[1]),
            poseidon_hash_many(secp256r1_pubk1), SECP256R1_SIGNER_TYPE
        ])
    change_webauthn_secp256r1_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('change_secp256r1_signer'),
        calldata=[
            *flatten_seq(new_webauthn_secp256r1_keypair[1]),
            poseidon_hash_many(webauthn_secp256r1_pubk1), WEBAUTHN_SIGNER_TYPE
        ])

    exec_txn = await account.execute(
        calls=[change_secp256r1_call, change_webauthn_secp256r1_call],
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    if multisig_threshold == 0:
        await assert_execute_fails_with_signer(account, balanceof_call,
                                               secp256r1_signer1,
                                               'INVALID_SIG')
        await assert_execute_fails_with_signer(account, balanceof_call,
                                               webauthn_secp256r1_signer1,
                                               'INVALID_SIG')

        account.signer = new_secp256r1_signer
        await execute_calls(account, balanceof_call)
        account.signer = secp256r1_signer2
        await execute_calls(account, balanceof_call)
        account.signer = new_webauthn_secp256r1_signer
        await execute_calls(account, balanceof_call)
        account.signer = webauthn_secp256r1_signer2
        await execute_calls(account, balanceof_call)
    if multisig_threshold == 2:
        await assert_execute_fails_with_signer(
            account, balanceof_call,
            create_multisig_signer(secp256r1_signer1,
                                   webauthn_secp256r1_signer1), 'INVALID_SIG')
        await assert_execute_fails_with_signer(
            account, balanceof_call,
            create_multisig_signer(secp256r1_signer1,
                                   webauthn_secp256r1_signer2), 'INVALID_SIG')
        await assert_execute_fails_with_signer(
            account, balanceof_call,
            create_multisig_signer(secp256r1_signer2,
                                   webauthn_secp256r1_signer1), 'INVALID_SIG')

        account.signer = create_multisig_signer(new_secp256r1_signer,
                                                new_webauthn_secp256r1_signer)
        await execute_calls(account, balanceof_call)
        account.signer = create_multisig_signer(new_secp256r1_signer,
                                                webauthn_secp256r1_signer2)
        await execute_calls(account, balanceof_call)
        account.signer = create_multisig_signer(secp256r1_signer2,
                                                new_webauthn_secp256r1_signer)
        await execute_calls(account, balanceof_call)
        account.signer = create_multisig_signer(secp256r1_signer2,
                                                webauthn_secp256r1_signer2)
        await execute_calls(account, balanceof_call)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "is_webauthn",
    ],
    [
        (True, ),
        (False, ),
    ],
    ids=[
        "webauthn",
        "not_webauthn",
    ],
)
async def test_duplicate_signers_cause_error(
    init_starknet,
    account_deployer,
    is_webauthn,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    stark_privk = random.randint(1, 10**10)
    secp256r1_keypair = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    account, _ = await account_deployer(stark_privk,
                                        secp256r1_pubk,
                                        2,
                                        is_webauthn=is_webauthn)
    account: Account

    stark_signer = create_stark_signer(stark_privk)
    secp256r1_signer = create_webauthn_signer(
        secp256r1_keypair[0]) if is_webauthn else create_secp256r1_signer(
            secp256r1_keypair[0])
    with pytest.raises(Exception, match="Account validation failed"):
        duplicate_signer1 = namedtuple('MultisigSigner', ['sign_transaction'])(
            lambda txn: [
                *stark_signer.sign_transaction(txn),
                # *secp256r1_signer.sign_transaction(txn),
                *stark_signer.sign_transaction(txn),
            ])

        account.signer = duplicate_signer1

        non_bypass_call = Call(to_addr=ETH_TOKEN_ADDRESS,
                               selector=get_selector_from_name("name"),
                               calldata=[])

        exec_txn = await account.execute(
            calls=[non_bypass_call],
            max_fee=int(0.1 * 10**18),
        )

        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    with pytest.raises(Exception, match="Account validation failed"):
        duplicate_signer1 = namedtuple('MultisigSigner', ['sign_transaction'])(
            lambda txn: [
                *secp256r1_signer.sign_transaction(txn),
                # *stark_signer.sign_transaction(txn),
                *secp256r1_signer.sign_transaction(txn),
            ])

        account.signer = duplicate_signer1

        non_bypass_call = Call(to_addr=ETH_TOKEN_ADDRESS,
                               selector=get_selector_from_name("name"),
                               calldata=[])

        exec_txn = await account.execute(
            calls=[non_bypass_call],
            max_fee=int(0.1 * 10**18),
        )

        await devnet_client.wait_for_tx(exec_txn.transaction_hash)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "secp256r1_keypair",
        "multisig_threshold",
        "is_webauthn",
    ],
    [
        (generate_secp256r1_keypair(), 0, False),
        (generate_secp256r1_keypair(), 2, False),
        (generate_secp256r1_keypair(), 0, True),
        (generate_secp256r1_keypair(), 2, True),
    ],
    ids=[
        "with_secp256r1_no_multisig",
        "with_secp256r1_multisig",
        "with_webauthn_secp256r1_no_multisig",
        "with_webauthn_secp256r1_multisig",
    ],
)
@pytest.mark.asyncio
async def test_setting_low_withdrawal_threshold_success(
    init_starknet,
    account_deployer,
    init_pricing_contract,
    set_and_assert_low_threshold,
    clean_token_config,
    get_required_signer_of_bypass_call,
    secp256r1_keypair,
    multisig_threshold,
    is_webauthn,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    stark_privk = random.randint(1, 10**10)
    secp256r1_pubk = flatten_seq(
        secp256r1_keypair[1]) if secp256r1_keypair is not None else None
    account, _ = await account_deployer(stark_privk,
                                        secp256r1_pubk,
                                        multisig_threshold,
                                        is_webauthn=is_webauthn)
    account: Account

    stark_signer = create_stark_signer(stark_privk)
    secp256r1_signer = create_webauthn_signer(
        secp256r1_keypair[0]) if is_webauthn else create_secp256r1_signer(
            secp256r1_keypair[0])
    if multisig_threshold == 0:
        account.signer = secp256r1_signer
    else:
        multisig_signer = create_multisig_signer(stark_signer,
                                                 secp256r1_signer)
        account.signer = multisig_signer

    await set_and_assert_low_threshold(100 * USDC, account)
    await clean_token_config(account)
    # 1 ETH == 100 USDC, Threshold is set to 100 USDC
    required_signer_for_bypass = await get_required_signer_of_bypass_call(
        account, amount=int(0.999999 * 10**18))
    assert required_signer_for_bypass == REQUIRED_SIGNER_STARK, 'Wrong required signer for bypass call'

    required_signer_for_bypass = await get_required_signer_of_bypass_call(
        account, amount=int(1.000001 * 10**18))
    assert required_signer_for_bypass == REQUIRED_SIGNER_MULTISIG if multisig_threshold == 2 else REQUIRED_SIGNER_STRONG, 'Wrong required signer for bypass call'


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "secp256r1_kp",
        "webauthn_kp",
        "multisig_threshold",
    ],
    [
        (None, None, 0),
        (generate_secp256r1_keypair(), None, 0),
        (None, generate_secp256r1_keypair(), 0),
        (generate_secp256r1_keypair(), None, 2),
        (None, generate_secp256r1_keypair(), 2),
        (generate_secp256r1_keypair(), generate_secp256r1_keypair(), 2),
    ],
    ids=[
        "stark_signer",
        "secp256r1_no_multisig",
        "webauthn_no_multisig",
        "stark_secp256r1_multisig",
        "stark_webauthn_multisig",
        "secp256r1_webauthn_multisig",
    ],
)
async def test_est_fee_sig_bypass(
    init_starknet,
    account_deployer,
    secp256r1_kp,
    webauthn_kp,
    multisig_threshold,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk, mock_est_fee=True)
    _ = create_legacy_stark_signer(stark_privk, mock_est_fee=True)
    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account
    account.signer = stark_signer
    webauthn_signer = None
    secp256r1_signer = None
    if secp256r1_kp is not None:
        secp256r1_pubk = flatten_seq(secp256r1_kp[1])
        await execute_calls(
            account,
            Call(
                to_addr=account.address,
                selector=get_selector_from_name("add_secp256r1_signer"),
                calldata=[*secp256r1_pubk, SECP256R1_SIGNER_TYPE, 0],
            ),
            max_fee=int(0.1 * 10**18),
        )
        secp256r1_signer = create_secp256r1_signer(secp256r1_kp[0],
                                                   mock_est_fee=True)
        account.signer = secp256r1_signer
    if webauthn_kp is not None:
        webauthn_pubk = flatten_seq(webauthn_kp[1])
        await execute_calls(
            account,
            Call(
                to_addr=account.address,
                selector=get_selector_from_name("add_secp256r1_signer"),
                calldata=[*webauthn_pubk, WEBAUTHN_SIGNER_TYPE, 0],
            ),
            max_fee=int(0.1 * 10**18),
        )
        webauthn_signer = create_webauthn_signer(webauthn_kp[0],
                                                 mock_est_fee=True)
        account.signer = webauthn_signer

    if multisig_threshold > 0:
        await execute_calls(
            account,
            Call(
                to_addr=account.address,
                selector=get_selector_from_name("set_multisig_threshold"),
                calldata=[multisig_threshold],
            ),
            max_fee=int(0.1 * 10**18),
        )
        if secp256r1_signer is None or webauthn_signer is None:
            signer_1 = stark_signer
            signer_2 = secp256r1_signer if secp256r1_signer is not None else webauthn_signer
        else:
            signer_1 = webauthn_signer
            signer_2 = secp256r1_signer

        multisig_signer = create_multisig_signer(signer_1, signer_2)
        account.signer = multisig_signer

    balanceof_call = Call(
        to_addr=int(FEE_CONTRACT_ADDRESS, 16),
        selector=get_selector_from_name('balanceOf'),
        calldata=[account.address],
    )

    invoke_txn = await account.sign_invoke_v1_transaction(
        balanceof_call,
        max_fee=int(0.0001 * 10**18),
    )
    invoke_est_fee = await account.sign_for_fee_estimate(invoke_txn)
    await devnet_client.estimate_fee(invoke_est_fee)


@pytest.mark.parametrize(
    [
        "secp256r1_keypair",
        "expected_error",
    ],
    [
        (None, 'INVALID_WITHDRAWAL_LIMIT_LOW'),
    ],
    ids=[
        "basic_stark_should_fail",
    ],
)
@pytest.mark.asyncio
async def test_setting_low_withdrawal_threshold_failure(
    init_starknet,
    account_deployer,
    init_pricing_contract,
    set_and_assert_low_threshold,
    secp256r1_keypair,
    expected_error,
):
    withdrawal_limit_low = 100 * USDC
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    stark_privk = random.randint(1, 10**10)
    secp256r1_pubk = flatten_seq(
        secp256r1_keypair[1]) if secp256r1_keypair is not None else None
    account, _ = await account_deployer(stark_privk, secp256r1_pubk, 0)
    account: Account

    signer = create_stark_signer(stark_privk)

    set_withdrawal_limit_low_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('set_withdrawal_limit_low'),
        calldata=[withdrawal_limit_low])

    await assert_execute_fails_with_signer(
        account,
        set_withdrawal_limit_low_call,
        signer,
        expected_error,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "secp256r1_keypair",
        "withdrawal_limit_high",
    ],
    [
        (generate_secp256r1_keypair(), 200 * USDC),
    ],
    ids=[
        "with_secp256r1_multisig",
    ],
)
async def test_setting_high_withdrawal_threshold_success(
    init_starknet,
    account_deployer,
    init_pricing_contract,
    get_daily_spend,
    set_and_assert_high_threshold,
    set_and_assert_low_threshold,
    clean_token_config,
    get_required_signer_of_bypass_call,
    secp256r1_keypair,
    withdrawal_limit_high,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    stark_privk = random.randint(1, 10**10)
    secp256r1_pubk = flatten_seq(
        secp256r1_keypair[1]) if secp256r1_keypair is not None else None
    account, _ = await account_deployer(stark_privk, secp256r1_pubk, 2, 0)
    account: Account

    multisig_signer = create_multisig_signer(
        create_stark_signer(stark_privk),
        create_secp256r1_signer(secp256r1_keypair[0]))
    account.signer = multisig_signer

    await set_and_assert_high_threshold(withdrawal_limit_high, account)
    await clean_token_config(account)
    # required_signer_for_bypass = await get_required_signer_of_bypass_call(account, amount=0)
    # assert required_signer_for_bypass == REQUIRED_SIGNER_STRONG, 'Wrong required signer for bypass call'

    # required_signer_for_bypass = await get_required_signer_of_bypass_call(account, amount = 3 * ETHER)
    # assert required_signer_for_bypass == REQUIRED_SIGNER_MULTISIG, 'Wrong required signer for bypass call'

    # fail with adding low threshold higher than high threshold
    extra_high = 300 * USDC
    set_withdrawal_limit_low_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('set_withdrawal_limit_low'),
        calldata=[extra_high])

    await assert_execute_fails_with_signer(
        account,
        set_withdrawal_limit_low_call,
        multisig_signer,
        "INVALID_WITHDRAWAL_LIMIT_LOW",
    )

    # succeed with adding low threshold lower than high threshold
    low_threshold = 100 * USDC
    await set_and_assert_low_threshold(low_threshold, account)

    # now that we have a low threshold we can sign with stark
    required_signer_for_bypass = await get_required_signer_of_bypass_call(
        account, amount=0)
    assert required_signer_for_bypass == REQUIRED_SIGNER_STARK, 'Wrong required signer for bypass call'

    required_signer_for_bypass = await get_required_signer_of_bypass_call(
        account, amount=int(1.0001 * 10**18))
    assert required_signer_for_bypass == REQUIRED_SIGNER_STRONG, 'Wrong required signer for bypass call'

    required_signer_for_bypass = await get_required_signer_of_bypass_call(
        account, amount=int(2.0001 * 10**18))
    assert required_signer_for_bypass == REQUIRED_SIGNER_MULTISIG, 'Wrong required signer for bypass call'

    # fail with setting lower high threshold
    high_threshold = 10 * USDC
    set_withdrawal_limit_high_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('set_withdrawal_limit_high'),
        calldata=[high_threshold])

    await assert_execute_fails_with_signer(
        account,
        set_withdrawal_limit_high_call,
        multisig_signer,
        "INVALID_HIGH_WITHDRAWAL_LIMIT",
    )

    # removing multisig and verifying that withdrawal limit is removed
    removing_multsig_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name("set_multisig_threshold"),
        calldata=[0],
    ),
    exec_txn = await account.execute(
        calls=removing_multsig_call,
        max_fee=int(0.1 * 10**18),
    )

    await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    exec_txn_receipt = await devnet_client.get_transaction_receipt(
        exec_txn.transaction_hash)
    assert txn_receipt_contains_event(
        exec_txn_receipt,
        [get_selector_from_name("WithdrawalLimitHighSet")],
        [0],
        True,
    ) is True, "no withdrawal limit set"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "secp256r1_keypair",
        "multisig_threshold",
        "withdrawal_limit_high",
        "expected_error",
    ],
    [
        (None, 0, 200 * USDC, 'INVALID_HIGH_WITHDRAWAL_LIMIT'),
        (generate_secp256r1_keypair(), 0, 200 * USDC,
         'INVALID_HIGH_WITHDRAWAL_LIMIT'),
    ],
    ids=[
        "basic_stark_should_fail",
        "with_secp256r1_no_multisig_should_fail",
    ],
)
async def test_setting_high_withdrawal_threshold_failure(
    init_starknet,
    account_deployer,
    init_pricing_contract,
    set_and_assert_high_threshold,
    set_and_assert_low_threshold,
    secp256r1_keypair,
    multisig_threshold,
    withdrawal_limit_high,
    expected_error,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    stark_privk = random.randint(1, 10**10)
    secp256r1_pubk = flatten_seq(
        secp256r1_keypair[1]) if secp256r1_keypair is not None else None
    account, _ = await account_deployer(stark_privk, secp256r1_pubk,
                                        multisig_threshold, 0)
    account: Account

    stark_signer = create_stark_signer(stark_privk)
    secp256r1_signer = create_secp256r1_signer(
        secp256r1_keypair[0]) if secp256r1_keypair is not None else None
    signer = stark_signer
    if secp256r1_keypair is None:
        signer = stark_signer
    elif multisig_threshold == 0:
        signer = secp256r1_signer
    else:
        signer = create_multisig_signer(stark_signer, secp256r1_signer)

    set_withdrawal_limit_high_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('set_withdrawal_limit_high'),
        calldata=[withdrawal_limit_high])

    await assert_execute_fails_with_signer(
        account,
        set_withdrawal_limit_high_call,
        signer,
        expected_error,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["multisig_threshold", "low_threshold", "high_threshold"],
    [
        (0, 100 * USDC, None),
        (2, 100 * USDC, None),
        (2, 100 * USDC, 200 * USDC),
    ],
    ids=[
        "with_secp256r1_no_multisig_no_high",
        "with_secp256r1_multisig_no_high",
        "with_secp256r1_multisig_with_high",
    ],
)
@pytest.mark.asyncio
async def test_removing_low_threshold(
    init_starknet,
    account_deployer,
    init_pricing_contract,
    set_and_assert_high_threshold,
    set_and_assert_low_threshold,
    multisig_threshold,
    low_threshold,
    high_threshold,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    stark_privk = random.randint(1, 10**10)
    secp256r1_keypair = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])

    account, _ = await account_deployer(stark_privk,
                                        secp256r1_pubk,
                                        multisig_threshold,
                                        withdrawal_limit_low=low_threshold,
                                        eth_fee_rate=100 * USDC,
                                        stark_fee_rate=100 * USDC)
    account: Account

    set_withdrawal_limit_low_call = Call(
        to_addr=account.address,
        selector=get_selector_from_name('set_withdrawal_limit_low'),
        calldata=[0])

    # fail with stark signer
    stark_signer = create_stark_signer(stark_privk)
    await assert_execute_fails_with_signer(
        account,
        set_withdrawal_limit_low_call,
        stark_signer,
        "INVALID_WITHDRAWAL_LIMIT_LOW",
    )

    secp256r1_signer = create_secp256r1_signer(secp256r1_keypair[0])
    if multisig_threshold == 0:
        account.signer = secp256r1_signer
    else:
        multisig_signer = create_multisig_signer(stark_signer,
                                                 secp256r1_signer)
        account.signer = multisig_signer

    if high_threshold is not None:
        await set_and_assert_high_threshold(high_threshold, account)

    await set_and_assert_low_threshold(0, account)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["lower_threshold", "high_threshold"],
    [
        (0, 100 * USDC),
        (100 * USDC, 200 * USDC),
    ],
    ids=[
        "without_existing_lower_threshold",
        "with_existing_lower_threshold",
    ],
)
@pytest.mark.asyncio
async def test_removing_high_threshold(
    init_starknet,
    init_pricing_contract,
    account_deployer,
    set_and_assert_high_threshold,
    lower_threshold,
    high_threshold,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient

    stark_privk = random.randint(1, 10**10)
    secp256r1_keypair = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    multisig_threshold = 2

    account, _ = await account_deployer(stark_privk,
                                        secp256r1_pubk,
                                        multisig_threshold,
                                        lower_threshold,
                                        eth_fee_rate=100 * USDC,
                                        stark_fee_rate=100 * USDC)
    account: Account

    stark_signer = create_stark_signer(stark_privk)
    secp256r1_signer = create_secp256r1_signer(secp256r1_keypair[0])
    multisig_signer = create_multisig_signer(stark_signer, secp256r1_signer)
    account.signer = multisig_signer
    await set_and_assert_high_threshold(high_threshold, account)
    await set_and_assert_high_threshold(0, account)


@pytest.mark.asyncio
async def test_pricing_contract(
    init_starknet,
    account_deployer,
    init_pricing_contract,
):
    _ = init_starknet


@pytest.mark.parametrize(
    [
        "call_type",
        "lower_threshold",
        "high_threshold",
        "multisig_threshold",
        "bypass_signer",
        "bypass_token_name",
        "is_webauthn",
    ],
    [
        ('transfer', 45 * USDC, 0, 2, 'stark', 'eth', True),
        ('transfer', 45 * USDC, 0, 0, 'stark', 'usdc', True),
        ('transfer', 45 * USDC, 0, 2, 'stark', 'usdc', True),
        ('transfer', 45 * USDC, 0, 2, 'hws', 'usdc', True),
        ('transfer', 0, 45 * USDC, 2, 'hws', 'usdc', True),
        ('transfer', 45 * USDC, 0, 2, 'hws', 'eth', True),
        ('transfer', 0, 45 * USDC, 2, 'hws', 'eth', True),
        ('transfer', 45 * USDC, 0, 0, 'stark', 'eth', True),
        ('transfer', 45 * USDC, 0, 2, 'stark', 'usdc', False),
        ('transfer', 45 * USDC, 0, 2, 'hws', 'usdc', False),
        ('transfer', 45 * USDC, 0, 0, 'stark', 'usdc', False),
        ('transfer', 0, 45 * USDC, 2, 'hws', 'usdc', False),
        ('transfer', 45 * USDC, 0, 2, 'stark', 'eth', False),
        ('transfer', 45 * USDC, 0, 2, 'hws', 'eth', False),
        ('transfer', 0, 45 * USDC, 2, 'hws', 'eth', False),
        ('transfer', 45 * USDC, 0, 0, 'stark', 'eth', False),
    ],
    ids=[
        "transfer_low_thresh_multisig_eth_with_stark_webauthn",
        "transfer_low_thresh_usdc_with_stark_webauthn",
        "transfer_low_thresh_multisig_usdc_with_stark_webauthn",
        "transfer_low_thresh_multisig_usdc_with_hws_webauthn",
        "transfer_high_thresh_multisig_usdc_with_hws_webauthn",
        "transfer_low_thresh_multisig_eth_with_hws_webauthn",
        "transfer_high_thresh_multisig_eth_with_hws_webauthn",
        "transfer_low_thresh_eth_with_hws_webauthn",
        "transfer_low_thresh_multisig_usdc_with_stark",
        "transfer_low_thresh_multisig_usdc_with_hws",
        "transfer_low_thresh_usdc_with_stark",
        "transfer_high_thresh_multisig_usdc_with_hws",
        "transfer_low_thresh_multisig_eth_with_stark",
        "transfer_low_thresh_multisig_eth_with_hws",
        "transfer_high_thresh_multisig_eth_with_hws",
        "transfer_low_thresh_eth_with_hws",
    ],
)
@pytest.mark.asyncio
async def test_successful_single_range_transfer(
    init_starknet,
    init_pricing_contract,
    account_deployer,
    mock_usdc_threshold_token,
    do_bypass,
    set_and_assert_high_threshold,
    get_fee_rate,
    get_daily_spend,
    clean_token_config,
    call_type,
    lower_threshold,
    high_threshold,
    multisig_threshold,
    bypass_signer,
    bypass_token_name,
    is_webauthn,
):
    token_address = ETH_TOKEN_ADDRESS if bypass_token_name == 'eth' else mock_usdc_threshold_token.address
    rate = 100 if bypass_token_name == 'eth' else 1
    fee_rate = 100
    fee_decimals_factor = 10**12  # usdc is 6 decimals, 18-6=12
    fee_rate_in_usdc_wei = fee_rate * USDC
    value_decimals_factor = 10**12 if bypass_token_name == 'eth' else 1

    max_fee = int(0.1 * 10**18)
    secp256r1_keypair = generate_secp256r1_keypair()

    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient

    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk)
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    secp256r1_signer = create_secp256r1_signer(
        secp256r1_keypair[0]) if not is_webauthn else create_webauthn_signer(
            secp256r1_keypair[0])
    account, _ = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_threshold,
        lower_threshold,
        is_webauthn=is_webauthn,
        eth_fee_rate=fee_rate_in_usdc_wei,
        stark_fee_rate=fee_rate_in_usdc_wei,
        erc20_address_to_transfer=mock_usdc_threshold_token.address)
    account: Account

    strong_signer = secp256r1_signer if multisig_threshold == 0 else create_multisig_signer(
        stark_signer, secp256r1_signer)

    account.signer = strong_signer

    if bypass_token_name == 'usdc':
        await clean_token_config(
            account, fake_usdc_address=mock_usdc_threshold_token.address)
    else:
        await clean_token_config(account)

    get_rate_result = await get_fee_rate(account)
    assert get_rate_result == (fee_rate_in_usdc_wei if lower_threshold > 0 else
                               0), "eth rate should exist right after ctor"

    bypass_signer = stark_signer if bypass_signer == 'stark' else secp256r1_signer

    if high_threshold > 0:
        account.signer = strong_signer
        await set_and_assert_high_threshold(high_threshold, account)

    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == 0, "daily threshold should be 0"

    # check that strong signer works and doesnt affect the daily spendenture
    account.signer = strong_signer
    transfer_call = Call(to_addr=token_address,
                         selector=get_selector_from_name(call_type),
                         calldata=[devnet_account.address, *to_uint256(1)])

    exec_txn = await account.execute(
        calls=transfer_call,
        max_fee=max_fee,
    )

    await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == 0, "no daily amount spent after strong signer"

    account.signer = bypass_signer
    await do_bypass(token_address, 0, account, bypass_signer, call_type)

    get_rate_result = await get_fee_rate(account)
    assert get_rate_result == fee_rate_in_usdc_wei, "incorrect rate"

    fee_spending = max_fee * fee_rate // fee_decimals_factor + 1
    extra_value = 1 if bypass_token_name == "eth" else 0
    daily_spend_result = await get_daily_spend(account)
    # extra 1 for the fee, and extra 1 for the value (only for eth, because usdc is the threshold currency)
    assert daily_spend_result == fee_spending, "daily threshold should only account for the fee since we moved a zero amount"

    account.signer = bypass_signer
    amount_to_transfer = ETHER // 10 if bypass_token_name == 'eth' else 10 * 10**6
    await do_bypass(token_address, amount_to_transfer, account, bypass_signer,
                    call_type)

    get_rate_result = await get_fee_rate(account)
    assert get_rate_result == fee_rate_in_usdc_wei, "rate should exist"

    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == 2 * fee_spending + amount_to_transfer * rate // value_decimals_factor + extra_value, "wrong daily threshold"

    with pytest.raises(Exception):
        await do_bypass(token_address, amount_to_transfer, account,
                        bypass_signer, call_type)

    # check the the fee was added on top of the daily spending
    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == 3 * fee_spending + amount_to_transfer * rate // value_decimals_factor + extra_value, "wrong daily threshold"

    # check that strong signer works
    strong_signer = secp256r1_signer if multisig_threshold == 0 else create_multisig_signer(
        stark_signer, secp256r1_signer)
    account.signer = strong_signer
    transfer_call = Call(
        to_addr=token_address,
        selector=get_selector_from_name(call_type),
        calldata=[devnet_account.address, *to_uint256(7 * 10**17)])

    exec_txn = await account.execute(
        calls=transfer_call,
        max_fee=int(0.1 * 10**18),
    )

    await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == 3 * fee_spending + amount_to_transfer * rate // value_decimals_factor + extra_value, "wrong daily threshold"

    # 2 days later
    requests.post(f"{devnet_url}/increase_time",
                  json={"time": int(2 * 24 * 60 * 60)})

    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == 0, "daily threshold should be zero after the day passes"


@pytest.mark.parametrize(
    ["call_type", "lower_threshold", "high_threshold", "bypass_token_name"],
    [
        ('transfer', 35 * USDC, 65 * USDC, 'usdc'),
        ('transfer', 35 * USDC, 65 * USDC, 'eth'),
    ],
    ids=[
        "transfer_usdc",
        "transfer_eth",
    ],
)
@pytest.mark.asyncio
async def test_successful_dual_threshold_transfer(
    init_starknet,
    account_deployer,
    init_pricing_contract,
    mock_usdc_threshold_token,
    do_bypass,
    set_and_assert_high_threshold,
    clean_token_config,
    get_fee_rate,
    get_daily_spend,
    call_type,
    lower_threshold,
    high_threshold,
    bypass_token_name,
):
    token_address = ETH_TOKEN_ADDRESS if bypass_token_name == 'eth' else mock_usdc_threshold_token.address
    rate = 100 if bypass_token_name == 'eth' else 1
    fee_rate = 100
    fee_decimals_factor = 10**12  # usdc is 6 decimals, 18-6=12
    fee_rate_in_wei = fee_rate * ETHER // fee_decimals_factor
    value_decimals_factor = 10**12 if bypass_token_name == 'eth' else 1
    max_fee = 0.1 * 10**18

    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient

    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk)
    secp256r1_keypair = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    secp256r1_signer = create_secp256r1_signer(secp256r1_keypair[0])
    multisig_threshold = 2

    account, _ = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_threshold,
        lower_threshold,
        erc20_address_to_transfer=mock_usdc_threshold_token.address,
        eth_fee_rate=fee_rate_in_wei,
        stark_fee_rate=fee_rate_in_wei,
    )
    account: Account

    multisig_signer = create_multisig_signer(stark_signer, secp256r1_signer)
    account.signer = multisig_signer
    if bypass_token_name == 'usdc':
        await clean_token_config(
            account, fake_usdc_address=mock_usdc_threshold_token.address)
    else:
        await clean_token_config(account)

    get_rate_result = await get_fee_rate(account)
    assert get_rate_result == fee_rate_in_wei, "eth rate should exist right after ctor"

    account.signer = multisig_signer
    await set_and_assert_high_threshold(high_threshold, account)

    bypass_signer = stark_signer
    amount_to_transfer = ETHER // 10 if bypass_token_name == 'eth' else 10 * 10**6

    await do_bypass(token_address, amount_to_transfer, account, bypass_signer,
                    call_type)
    extra_value = 1 if bypass_token_name == "eth" else 0
    fee_spending = max_fee * fee_rate // fee_decimals_factor + 1

    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == fee_spending + amount_to_transfer * rate // value_decimals_factor + extra_value, "wrong daily spend"

    with pytest.raises(Exception):
        await do_bypass(token_address, amount_to_transfer, account,
                        bypass_signer, call_type)

    # now trying with the stronger signer
    bypass_signer = secp256r1_signer
    await do_bypass(token_address, amount_to_transfer, account, bypass_signer,
                    call_type)

    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == 3 * fee_spending + 2 * amount_to_transfer * rate // value_decimals_factor + 2 * extra_value, "wrong daily spend"

    with pytest.raises(Exception):
        await do_bypass(token_address, amount_to_transfer, account,
                        bypass_signer, call_type)

    daily_spend_result = await get_daily_spend(account)

    # check that strong signer works
    account.signer = multisig_signer
    transfer_call = Call(
        to_addr=token_address,
        selector=get_selector_from_name(call_type),
        calldata=[devnet_account.address, *to_uint256(amount_to_transfer)])

    exec_txn = await account.execute(
        calls=transfer_call,
        max_fee=int(0.1 * 10**18),
    )

    await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == 4 * fee_spending + 2 * amount_to_transfer * rate // value_decimals_factor + 2 * extra_value, "wrong dialy spend"

    # 2 days later
    requests.post(f"{devnet_url}/increase_time",
                  json={"time": int(2 * 24 * 60 * 60)})

    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == 0, "daily threshold should be zero after the day passes"


@pytest.mark.parametrize(
    ["call_type"],
    [
        ('transfer', ),
    ],
    ids=[
        "transfer",
    ],
)
@pytest.mark.asyncio
async def test_non_whitelisted_token_cannot_bypass(
    init_starknet,
    account_deployer,
    init_pricing_contract,
    pepe_token,
    do_bypass,
    call_type,
):
    lower_threshold = 100 * 10**18
    rate = 100
    rate_in_wei = rate * ETHER

    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient

    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk)
    secp256r1_keypair = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    multisig_threshold = 0

    account, _ = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_threshold,
        lower_threshold,
        eth_fee_rate=rate_in_wei,
        stark_fee_rate=rate_in_wei,
    )
    account: Account

    with pytest.raises(ClientError, match=encode_string_as_hex('INVALID_SIG')):
        await do_bypass(pepe_token.address, 7 * 10**17, account, stark_signer,
                        call_type)


@pytest.mark.asyncio
async def test_bad_calls_structure_cant_bypass(
    init_starknet,
    init_pricing_contract,
    account_deployer,
    do_bypass,
):
    lower_threshold = 100 * 10**18
    rate = 100
    rate_in_wei = rate * ETHER

    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient

    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk)
    secp256r1_keypair = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    multisig_threshold = 2

    account, _ = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_threshold,
        lower_threshold,
        eth_fee_rate=rate_in_wei,
        stark_fee_rate=rate_in_wei,
    )
    account: Account

    with pytest.raises(ClientError, match=encode_string_as_hex('INVALID_SIG')):
        account.signer = stark_signer

        non_bypass_call = Call(
            to_addr=0,
            selector=get_selector_from_name("get_total_number_of_pools"),
            calldata=[])

        exec_txn = await account.execute(
            calls=[non_bypass_call],
            max_fee=int(0.1 * 10**18),
        )

        await devnet_client.wait_for_tx(exec_txn.transaction_hash)


@pytest.mark.asyncio
async def test_bad_transfer_call(
    init_starknet,
    account_deployer,
    do_bypass,
):
    lower_threshold = 100 * 10**18
    rate = 100
    rate_in_wei = rate * ETHER

    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient

    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk)
    secp256r1_keypair = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    multisig_threshold = 2

    account, _ = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_threshold,
        lower_threshold,
        eth_fee_rate=rate_in_wei,
        stark_fee_rate=rate_in_wei,
    )
    account: Account
    account.signer = stark_signer
    with pytest.raises(ClientError, match=encode_string_as_hex('INVALID_SIG')):

        # transfer has 3 felt input but here i'm passing just 2
        malfunctioned_transfer_call = Call(
            to_addr=ETH_TOKEN_ADDRESS,
            selector=get_selector_from_name("transfer"),
            calldata=[0, 10**17])

        exec_txn = await account.execute(
            calls=[malfunctioned_transfer_call],
            max_fee=int(0.1 * 10**18),
        )

        await devnet_client.wait_for_tx(exec_txn.transaction_hash)


@pytest.mark.parametrize(
    [
        "call_type",
        "fee_rate_input",
    ],
    [
        ('transfer', 50),
        ('transfer', 150),
        ('transfer', 98),
        ('transfer', 102),
    ],
    ids=[
        "transfer_lower_rate",
        "transfer_higher_rate",
        "transfer_lower_close_rate",
        "transfer_higher_close_rate",
    ],
)
@pytest.mark.asyncio
async def test_changing_rate_works(
    init_starknet,
    account_deployer,
    init_pricing_contract,
    clean_token_config,
    get_fee_rate,
    get_daily_spend,
    do_bypass,
    call_type,
    fee_rate_input,
):
    max_fee = 10**17
    fee_rate_input_in_wei = fee_rate_input * USDC

    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient

    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk)
    secp256r1_keypair = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    multisig_threshold = 0

    account, _ = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_threshold,
        100 * USDC,
        eth_fee_rate=fee_rate_input_in_wei,
        stark_fee_rate=100 * fee_rate_input_in_wei,
    )
    account: Account
    secp256r1_signer = create_secp256r1_signer(secp256r1_keypair[0])
    account.signer = secp256r1_signer
    await clean_token_config(account)
    current_fee_rate = await get_fee_rate(account)
    assert current_fee_rate == fee_rate_input_in_wei, 'fee rate should be the original one given in ctor'

    current_fee_rate_stark = await get_fee_rate(account, token_name="stark")
    amount_to_transfer = 10**17
    await do_bypass(ETH_TOKEN_ADDRESS, amount_to_transfer, account,
                    stark_signer, call_type)

    actual_fee_rate = 100
    actual_fee_rate_in_wei = actual_fee_rate * USDC
    current_fee_rate = await get_fee_rate(account)
    if abs(actual_fee_rate_in_wei -
           fee_rate_input_in_wei) < fee_rate_input_in_wei * 0.05:
        assert current_fee_rate == fee_rate_input_in_wei, 'wrong fee rate'
    else:
        assert current_fee_rate == actual_fee_rate_in_wei, 'wrong fee rate'

    daily_spend = await get_daily_spend(account)
    assert daily_spend == max_fee * actual_fee_rate // 10**12 + amount_to_transfer * actual_fee_rate // 10**12 + 2, 'daily spending should be based on updated rate regardless of rate storage changes'
    current_fee_rate_stark = await get_fee_rate(account, token_name="stark")
    assert current_fee_rate_stark == 100 * fee_rate_input_in_wei, 'stark fee should not have changed'


@pytest.mark.asyncio
async def test_transfer_amount_too_large_for_u128(
    init_starknet,
    init_pricing_contract,
    account_deployer,
    clean_token_config,
    do_bypass,
):
    lower_threshold = 100 * 10**18
    fee_rate_input_in_wei = 100 * ETHER

    _, _, _ = init_starknet

    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk)
    secp256r1_keypair = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    multisig_threshold = 0

    account, _ = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_threshold,
        lower_threshold,
        eth_fee_rate=fee_rate_input_in_wei,
        stark_fee_rate=fee_rate_input_in_wei,
    )
    account: Account
    secp256r1_signer = create_secp256r1_signer(secp256r1_keypair[0])
    account.signer = secp256r1_signer
    await clean_token_config(account)

    amount_to_transfer = 2**129
    with pytest.raises(TransactionRevertedError):
        await do_bypass(ETH_TOKEN_ADDRESS, amount_to_transfer, account,
                        stark_signer, "transfer")


@pytest.mark.parametrize(
    [
        "lower_threshold",
        "high_threshold",
        "multisig_threshold",
        "bypass_signer",
    ],
    [
        (55 * USDC, 0, 2, 'stark'),
        (55 * USDC, 0, 2, 'hws'),
        (55 * USDC, 0, 0, 'stark'),
        (0, 55 * USDC, 2, 'hws'),
        (15 * USDC, 55 * USDC, 2, 'hws'),
    ],
    ids=[
        "low_thresh_multisig_with_stark",
        "low_thresh_multisig_with_hws",
        "low_thresh_no_multsig_with_stark",
        "high_thresh_multisig_with_hws",
        "low_high_thresh_multisig_with_hws",
    ],
)
@pytest.mark.asyncio
async def test_successful_multicall(
    init_starknet,
    account_deployer,
    init_pricing_contract,
    mock_usdc_threshold_token,
    do_single_bypass_multicall,
    do_double_bypass_multicall,
    set_and_assert_high_threshold,
    clean_token_config,
    get_fee_rate,
    get_daily_spend,
    lower_threshold,
    high_threshold,
    multisig_threshold,
    bypass_signer,
):
    rate_in_wei = 100 * USDC
    max_fee = int(0.1 * 10**18)
    secp256r1_keypair = generate_secp256r1_keypair()

    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient

    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk)
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    secp256r1_signer = create_secp256r1_signer(secp256r1_keypair[0])
    multisig_signer = create_multisig_signer(stark_signer, secp256r1_signer)
    strong_signer = multisig_signer if multisig_threshold == 2 else secp256r1_signer

    account, _ = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_threshold,
        lower_threshold,
        eth_fee_rate=rate_in_wei,
        stark_fee_rate=rate_in_wei,
        erc20_address_to_transfer=mock_usdc_threshold_token.address)
    account: Account

    account.signer = strong_signer
    await clean_token_config(
        account,
        fake_usdc_address=mock_usdc_threshold_token.address,
        add_custom_call_double=False)

    bypass_signer = stark_signer if bypass_signer == 'stark' else secp256r1_signer

    if high_threshold > 0:
        account.signer = secp256r1_signer if multisig_threshold == 0 else create_multisig_signer(
            stark_signer, secp256r1_signer)
        await set_and_assert_high_threshold(high_threshold, account)

    get_rate_result = await get_fee_rate(account)
    assert get_rate_result == rate_in_wei, "eth rate should exist right after ctor"

    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == 0, "daily threshold should be 0"

    # check that strong signer works and doesnt affect the dialy spendenture
    strong_signer = secp256r1_signer if multisig_threshold == 0 else multisig_signer

    account.signer = strong_signer
    transfer_call = Call(to_addr=ETH_TOKEN_ADDRESS,
                         selector=get_selector_from_name("transfer"),
                         calldata=[devnet_account.address, *to_uint256(1)])

    exec_txn = await account.execute(
        calls=transfer_call,
        max_fee=max_fee,
    )

    await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == 0, "no daily amount spent after strong signer"

    await do_single_bypass_multicall(100, ETH_TOKEN_ADDRESS, account,
                                     bypass_signer)

    get_rate_result = await get_fee_rate(account)
    assert get_rate_result == rate_in_wei, "rate should exist"

    expected_fee_spending = max_fee * rate_in_wei // (ETHER) + 1
    daily_spend_result = await get_daily_spend(account)
    assert abs(daily_spend_result -
               (expected_fee_spending + 1)) <= 10, "wrong daily threshold"

    await clean_token_config(
        account,
        fake_usdc_address=mock_usdc_threshold_token.address,
        add_custom_call_double=True)

    await do_double_bypass_multicall(100, ETH_TOKEN_ADDRESS, 100,
                                     mock_usdc_threshold_token.address,
                                     account, bypass_signer)

    get_rate_result = await get_fee_rate(account)
    assert get_rate_result == rate_in_wei, "rate should exist"

    expected_fee_spending += max_fee * rate_in_wei // (ETHER) + 1
    daily_spend_result = await get_daily_spend(account)
    assert abs(daily_spend_result -
               (expected_fee_spending + 1)) <= 10, "wrong daily threshold"


@pytest.mark.asyncio
async def test_multicall_bypass_failures(
    init_starknet,
    account_deployer,
    init_pricing_contract,
    mock_usdc_threshold_token,
    do_single_bypass_multicall,
    do_double_bypass_multicall,
    set_and_assert_high_threshold,
    clean_token_config,
    get_fee_rate,
    get_daily_spend,
):
    pricing_contract_address, _, _ = init_pricing_contract
    rate_in_wei = 100 * USDC
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient

    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk)
    secp256r1_keypair = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    secp256r1_signer = create_secp256r1_signer(secp256r1_keypair[0])
    lower_threshold = 500 * USDC

    account, _ = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        0,
        lower_threshold,
        eth_fee_rate=rate_in_wei,
        stark_fee_rate=rate_in_wei,
        erc20_address_to_transfer=mock_usdc_threshold_token.address)
    account: Account

    # approves must be to the white listed call address - single approve
    account.signer = secp256r1_signer
    await clean_token_config(
        account,
        fake_usdc_address=mock_usdc_threshold_token.address,
        add_custom_call_double=False)
    bad_approve_bypass_call = Call(
        to_addr=ETH_TOKEN_ADDRESS,
        selector=get_selector_from_name("approve"),
        calldata=[101010, *to_uint256(100)],
    )
    custom_call = Call(
        to_addr=pricing_contract_address,
        selector=get_selector_from_name("get_average_price"),
        calldata=[0, 0],
    )

    account.signer = stark_signer
    with pytest.raises(ClientError, match=encode_string_as_hex("INVALID_SIG")):
        exec_txn = await account.execute(
            calls=[
                bad_approve_bypass_call,
                custom_call,
            ],
            max_fee=int(0.1 * 10**18),
        )
        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    # approves must be to the white listed call address - double approve
    account.signer = secp256r1_signer
    await clean_token_config(
        account,
        fake_usdc_address=mock_usdc_threshold_token.address,
        add_custom_call_double=True)
    good_approve_bypass_call = Call(
        to_addr=ETH_TOKEN_ADDRESS,
        selector=get_selector_from_name("approve"),
        calldata=[pricing_contract_address, *to_uint256(100)],
    )
    bad_second_approve_bypass_call = Call(
        to_addr=mock_usdc_threshold_token.address,
        selector=get_selector_from_name("approve"),
        calldata=[10100101, *to_uint256(100)],
    )
    custom_call = Call(
        to_addr=pricing_contract_address,
        selector=get_selector_from_name("get_average_price"),
        calldata=[0, 0],
    )

    account.signer = stark_signer
    with pytest.raises(ClientError, match=encode_string_as_hex("INVALID_SIG")):
        exec_txn = await account.execute(
            calls=[
                good_approve_bypass_call,
                bad_approve_bypass_call,
                custom_call,
            ],
            max_fee=int(0.1 * 10**18),
        )
        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    # can't send the same approve twice
    account.signer = secp256r1_signer
    await clean_token_config(
        account,
        fake_usdc_address=mock_usdc_threshold_token.address,
        add_custom_call_double=True)
    approve_bypass_call1 = Call(
        to_addr=ETH_TOKEN_ADDRESS,
        selector=get_selector_from_name("approve"),
        calldata=[pricing_contract_address, *to_uint256(100)])
    approve_bypass_call2 = Call(
        to_addr=ETH_TOKEN_ADDRESS,
        selector=get_selector_from_name("approve"),
        calldata=[pricing_contract_address, *to_uint256(100)])
    custom_call = Call(to_addr=pricing_contract_address,
                       selector=get_selector_from_name("get_average_price"),
                       calldata=[0, 0])

    account.signer = stark_signer
    with pytest.raises(ClientError, match=encode_string_as_hex("INVALID_SIG")):
        exec_txn = await account.execute(
            calls=[
                approve_bypass_call1,
                approve_bypass_call2,
                custom_call,
            ],
            max_fee=int(0.1 * 10**18),
        )
        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    # can't send double white listed call when single is whitlisted
    account.signer = secp256r1_signer
    await clean_token_config(
        account,
        fake_usdc_address=mock_usdc_threshold_token.address,
        add_custom_call_double=False)
    approve_bypass_call1 = Call(
        to_addr=ETH_TOKEN_ADDRESS,
        selector=get_selector_from_name("approve"),
        calldata=[pricing_contract_address, *to_uint256(100)])
    approve_bypass_call2 = Call(
        to_addr=ETH_TOKEN_ADDRESS,
        selector=get_selector_from_name("approve"),
        calldata=[pricing_contract_address, *to_uint256(100)])
    custom_call = Call(to_addr=pricing_contract_address,
                       selector=get_selector_from_name("get_average_price"),
                       calldata=[0, 0])

    account.signer = stark_signer
    with pytest.raises(ClientError, match=encode_string_as_hex("INVALID_SIG")):
        exec_txn = await account.execute(
            calls=[
                approve_bypass_call1,
                approve_bypass_call2,
                custom_call,
            ],
            max_fee=int(0.1 * 10**18),
        )
        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    # can't send single white listed call when double is whitlisted
    account.signer = secp256r1_signer
    await clean_token_config(
        account,
        fake_usdc_address=mock_usdc_threshold_token.address,
        add_custom_call_double=True)
    good_approve_bypass_call = Call(
        to_addr=ETH_TOKEN_ADDRESS,
        selector=get_selector_from_name("approve"),
        calldata=[pricing_contract_address, *to_uint256(100)])

    custom_call = Call(to_addr=pricing_contract_address,
                       selector=get_selector_from_name("get_average_price"),
                       calldata=[0, 0])

    account.signer = stark_signer
    with pytest.raises(ClientError, match=encode_string_as_hex("INVALID_SIG")):
        exec_txn = await account.execute(
            calls=[
                good_approve_bypass_call,
                custom_call,
            ],
            max_fee=int(0.1 * 10**18),
        )
        await devnet_client.wait_for_tx(exec_txn.transaction_hash)


@pytest.mark.asyncio
async def test_get_required_signer(
    init_starknet,
    account_deployer,
    init_pricing_contract,
    clean_token_config,
    mock_usdc_threshold_token,
    set_and_assert_high_threshold,
    get_required_signer_of_bypass_call,
):
    lower_threshold = 55 * USDC
    high_threshold = 250 * USDC
    max_fee = 10**17
    rate_in_wei = 100 * USDC

    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient

    _, set_price, _ = init_pricing_contract

    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk)
    secp256r1_keypair = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    secp256r1_signer = create_secp256r1_signer(secp256r1_keypair[0])
    multisig_signer = create_multisig_signer(stark_signer, secp256r1_signer)
    multisig_threshold = 2

    account, _ = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_threshold,
        lower_threshold,
        erc20_address_to_transfer=mock_usdc_threshold_token.address,
        eth_fee_rate=rate_in_wei,
        stark_fee_rate=rate_in_wei)
    account: Account

    account.signer = multisig_signer

    await set_and_assert_high_threshold(high_threshold, account)
    await clean_token_config(account)

    USDC_ADDR = 0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8
    await set_price(
        compute_myswap_cl_pool_key(int(FEE_CONTRACT_ADDRESS, 16), USDC_ADDR,
                                   500), 86400,
        compute_myswap_cl_to_usdc_price(target_rate_usdc_for_token=1000 // 1,
                                        token_decimal=18,
                                        is_usdc_token0=False))

    # start with a stored rate lower than actual price service rate
    required_signer = await get_required_signer_of_bypass_call(account,
                                                               amount=0)
    assert required_signer == REQUIRED_SIGNER_STARK

    required_signer = await get_required_signer_of_bypass_call(account,
                                                               amount=10**17,
                                                               fee=10**17)
    assert required_signer == REQUIRED_SIGNER_STRONG

    required_signer = await get_required_signer_of_bypass_call(account,
                                                               amount=2 *
                                                               10**17,
                                                               fee=2 * 10**17)
    assert required_signer == REQUIRED_SIGNER_MULTISIG

    await set_price(
        compute_myswap_cl_pool_key(int(FEE_CONTRACT_ADDRESS, 16), USDC_ADDR,
                                   500), 86400,
        compute_myswap_cl_to_usdc_price(target_rate_usdc_for_token=10 // 1,
                                        token_decimal=18,
                                        is_usdc_token0=False))

    # now the stored rate is higher than the price service
    required_signer = await get_required_signer_of_bypass_call(account,
                                                               amount=0,
                                                               fee=0)
    assert required_signer == REQUIRED_SIGNER_STARK

    required_signer = await get_required_signer_of_bypass_call(account,
                                                               amount=10**18,
                                                               fee=10**18)
    assert required_signer == REQUIRED_SIGNER_STRONG

    required_signer = await get_required_signer_of_bypass_call(account,
                                                               amount=5 *
                                                               10**18,
                                                               fee=3 * 10**18)
    assert required_signer == REQUIRED_SIGNER_MULTISIG


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "auth_data",
        "client_data",
        "challenge_hash",
        "webauthn_pubk",
        "sig",
    ],
    [
        (
            [
                116, 166, 234, 146, 19, 201, 156, 47, 116, 178, 36, 146, 179,
                32, 207, 64, 38, 42, 148, 193, 169, 80, 160, 57, 127, 41, 37,
                11, 96, 132, 30, 240, 5, 0, 0, 0, 0
            ],
            b'{"type":"webauthn.get","challenge":"AxoM-tTPIX18lTegTTaING0vqt-zGTo2280Pvp7wv1Q","origin":"https://webauthn.io","crossOrigin":false}',
            0x031a0cfad4cf217d7c9537a04d3688346d2faadfb3193a36dbcd0fbe9ef0bf54,
            (0xf9283b5626fbfbd9ce37a99e1dcddd827af70e29ebef4b36da72d67529dcfc0b,
             0x6a2cb06fe59dea25ddde7c85d91fe265d532c4d61c693f630e7d779ee27b37d0
             ),
            (0x36e87cd4437a08e0423aee82d65b723a86ed74ddaf11213a5a0dc5c192a563dc,
             0x1d2e845b18aef79f81c18181eeacc6b4fc9fa2cea011e3e7a92ba32eef643e1d
             ),
        ),
        (
            [
                116, 166, 234, 146, 19, 201, 156, 47, 116, 178, 36, 146, 179,
                32, 207, 64, 38, 42, 148, 193, 169, 80, 160, 57, 127, 41, 37,
                11, 96, 132, 30, 240, 5, 0, 0, 0, 0
            ],
            b'{"type":"webauthn.get","challenge":"Ao2tfRQgmHqiZysS8zunBgcWwnjXSntgzUi5ofvYd2w","origin":"https://webauthn.io","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}',
            0x028dad7d1420987aa2672b12f33ba7060716c278d74a7b60cd48b9a1fbd8776c,
            (0xf9283b5626fbfbd9ce37a99e1dcddd827af70e29ebef4b36da72d67529dcfc0b,
             0x6a2cb06fe59dea25ddde7c85d91fe265d532c4d61c693f630e7d779ee27b37d0
             ),
            (0x3b429033efb080d067c15a20304e7283f3ce2a4fc837897ab59c9ecbfd53b8d8,
             0x5c6b1e0d1f16e2b318888d71a35a9654accf571961423a1f5732fbd469d0df82
             ),
        ),
    ],
    ids=[
        "test_case_1",
        "test_case_2_additional_fields_in_cdata",
    ],
)
async def test_webauthn_chromium_examples(
    init_starknet,
    account_deployer,
    auth_data,
    client_data,
    challenge_hash,
    webauthn_pubk,
    sig,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk, mock_est_fee=True)
    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account
    account.signer = stark_signer
    pk_x_uint256 = to_uint256(webauthn_pubk[0])
    pk_y_uint256 = to_uint256(webauthn_pubk[1])
    await execute_calls(
        account,
        Call(
            to_addr=account.address,
            selector=get_selector_from_name("add_secp256r1_signer"),
            calldata=[*pk_x_uint256, *pk_y_uint256, WEBAUTHN_SIGNER_TYPE, 0],
        ),
    )

    hash_binstr = bin(challenge_hash).lstrip('0b')
    hash_8bit_align = (8 - len(hash_binstr) % 8) % 8
    hash_6bit_align = (6 - (len(hash_binstr) + hash_8bit_align) % 6) % 6
    base64_padding = 0 if hash_6bit_align == 0 else 2**hash_6bit_align
    base64_challenge = base64.urlsafe_b64encode(
        challenge_hash.to_bytes((challenge_hash.bit_length() + 7) // 8,
                                'big')).rstrip(b'=')
    base64_challenge_ascii = base64_challenge.decode('ascii')
    challenge_offset = client_data.find(base64_challenge)
    for force_cairo_impl in [0, 1]:
        adata_u32s = u8s_to_u32s_padded([b for b in auth_data])
        cdata_u32s = u8s_to_u32s_padded([b for b in client_data])
        contract_sig = [
            WEBAUTHN_SIGNER_TYPE, *pk_x_uint256, *pk_y_uint256,
            len(adata_u32s[0]), *adata_u32s[0], adata_u32s[1],
            len(cdata_u32s[0]), *cdata_u32s[0], cdata_u32s[1],
            challenge_offset,
            len(base64_challenge_ascii), base64_padding, *to_uint256(sig[0]),
            *to_uint256(sig[1]), force_cairo_impl
        ]

        call_res = await devnet_client.call_contract(
            Call(
                to_addr=account.address,
                selector=get_selector_from_name("is_valid_signature"),
                calldata=[challenge_hash,
                          len(contract_sig), *contract_sig],
            ))

        assert call_res[0] == int.from_bytes(b'VALID', 'big')


@pytest.mark.asyncio
async def test_external_entrypoints_assert_self(init_starknet,
                                                account_deployer,
                                                account_contracts_str):
    devnet_url, devnet_client, devnet_account = init_starknet
    _, _, account_sierra_str, _ = account_contracts_str
    devnet_client: FullNodeClient
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk, mock_est_fee=True)
    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account

    account_abi = json.loads(account_sierra_str)["abi"]
    account_external_entrypoints = [
        x["name"] for y in account_abi if y["type"] == "interface"
        for x in y["items"]
        if x["type"] == "function" and x["state_mutability"] == "external"
    ]

    # manual because it's much easier to deduce num of felt252 inputs to a function manually than
    # parsing the abi with code and recursing through types
    external_entrypoints = [
        ("__validate__", 1, "NO_REENTRANCE"),
        ("__execute__", 1, "NO_REENTRANCE"),
        ("initializer", 1, "ALREADY_INITIALIZED"),
        ("set_withdrawal_limit_low", 1, "INVALID_CALLER"),
        ("set_withdrawal_limit_high", 1, "INVALID_CALLER"),
        ("update_rate_config", 1 + 1, "INVALID_CALLER"),
        ("add_secp256r1_signer", 4 + 1 + 1, "INVALID_CALLER"),
        ("remove_secp256r1_signer", 1 + 1 + 1, "INVALID_CALLER"),
        ("change_secp256r1_signer", 4 + 1 + 1, "INVALID_CALLER"),
        ("deferred_remove_signers", 0, "INVALID_CALLER"),
        ("cancel_deferred_remove_signers", 0, "INVALID_CALLER"),
        ("set_execution_time_delay", 1, "INVALID_CALLER"),
        ("set_multisig_threshold", 1, "INVALID_CALLER"),
        ("upgrade", 1, "INVALID_CALLER"),
        ("migrate_storage", 1, "INVALID_CALLER"),
        ("get_required_signer", 3, "INVALID_CALLER"),
    ]
    # since it's manual, let's assert that we have full coverage
    entrypoint_coverage = set(account_external_entrypoints) - set(
        x[0] for x in external_entrypoints)
    entrypoint_coverage -= set(["execute_from_outside_v2"
                                ])  # checked separately
    assert entrypoint_coverage == set(
    ), f"not all external entrypoints are covered {entrypoint_coverage}"

    for (entrypoint, num_params, error_message) in external_entrypoints:
        with pytest.raises(Exception, match=error_message):
            await devnet_account.execute(
                Call(
                    to_addr=account.address,
                    selector=get_selector_from_name(entrypoint),
                    calldata=[0] * num_params,
                ),
                auto_estimate=True,
            )


def get_transfer_call(address, transfer_amount):
    return Call(
        to_addr=int(FEE_CONTRACT_ADDRESS, 16),
        selector=get_selector_from_name("transfer"),
        calldata=[address, transfer_amount, 0],
    )


class OutsideExecution:

    def __init__(
        self,
        caller: int = int.from_bytes(b"ANY_CALLER", byteorder="big"),
        nonce=0,
        execute_after=time.time() - 1000,
        execute_before=time.time() + 1000,
        calls: List[Call] = [get_transfer_call(0x1, 1)],
    ):
        self.caller = caller
        self.nonce = nonce
        self.execute_after = int(execute_after)
        self.execute_before = int(execute_before)
        self.calls = calls
        self.sig = []
        self.typed_data = TypedDataR1({
            "OutsideExecution": [
                {
                    "name": "Caller",
                    "type": "ContractAddress"
                },
                {
                    "name": "Nonce",
                    "type": "felt"
                },
                {
                    "name": "Execute After",
                    "type": "u128"
                },
                {
                    "name": "Execute Before",
                    "type": "u128"
                },
                {
                    "name": "Calls",
                    "type": "Call*"
                },
            ],
            "Call": [
                {
                    "name": "To",
                    "type": "ContractAddress"
                },
                {
                    "name": "Selector",
                    "type": "selector"
                },
                {
                    "name": "Calldata",
                    "type": "felt*"
                },
            ],
        })

    def parse_calls_for_outside_exec_hash(self, calls):
        calls_parsed = []
        for call in calls:
            _data = {
                "To": call.to_addr,
                "Selector": call.selector,
                "Calldata": call.calldata,
            }
            calls_parsed.append(_data)

        return calls_parsed

    def get_hash(self, account_address):
        message = {
            "Caller":
            self.caller,
            "Nonce":
            self.nonce,
            "Execute After":
            self.execute_after,
            "Execute Before":
            self.execute_before,
            "Calls":
            self.parse_calls_for_outside_exec_hash(ensure_iterable(self.calls))
        }
        return self.typed_data.get_hash(message, account_address)

    def get_serialized_calls(self):
        parsed_calls = _parse_calls_v2(ensure_iterable(self.calls))
        return _execute_payload_serializer_v2.serialize(
            {"calls": parsed_calls})

    def get_calldata(self):
        return [
            self.caller,
            self.nonce,
            self.execute_after,
            self.execute_before,
            *self.get_serialized_calls(),
            len(self.sig),
            *self.sig,
        ]

    def prepare_call(self, account_address):
        return Call(
            to_addr=account_address,
            selector=get_selector_from_name("execute_from_outside_v2"),
            calldata=self.get_calldata(),
        )

    def sign_stark(self, account_address, stark_privk):
        self.sig.extend(
            sign_hash_stark(self.get_hash(account_address), stark_privk))

    def sign_ecc(self, account_address, ecc_key, signer_type):
        if signer_type == SECP256R1_SIGNER_TYPE:
            self.sig.extend(
                sign_hash_secp256r1(self.get_hash(account_address), ecc_key))
        elif signer_type == WEBAUTHN_SIGNER_TYPE:
            self.sig.extend(
                sign_hash_webauthn(self.get_hash(account_address), ecc_key))


async def validate_outside_nonce(client, address, nonce, expected_res):
    res = await client.call_contract(
        Call(
            to_addr=address,
            selector=get_selector_from_name(
                "is_valid_outside_execution_nonce"),
            calldata=[nonce],
        ), )
    assert res[0] == expected_res, "Nonce validation failed"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "second_signer_type",
        "multisig_threshold",
    ],
    [
        (None, 0),
        (SECP256R1_SIGNER_TYPE, 0),
        (SECP256R1_SIGNER_TYPE, 2),
        (WEBAUTHN_SIGNER_TYPE, 0),
        (WEBAUTHN_SIGNER_TYPE, 2),
    ],
    ids=[
        "no_second_signer_no_multisig",
        "with_secp256r1_no_multisig",
        "with_secp256r1_multisig",
        "with_webauthn_no_multisig",
        "with_webauthn_multisig",
    ],
)
async def test_outside_execution(
    init_starknet,
    account_deployer,
    second_signer_type,
    multisig_threshold,
):
    _, devnet_client, devnet_account = init_starknet

    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account

    secp256r1_keypair = generate_secp256r1_keypair()
    if second_signer_type:
        secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
        add_secp256r1_call = Call(
            to_addr=account.address,
            selector=get_selector_from_name("add_secp256r1_signer"),
            calldata=[*secp256r1_pubk, second_signer_type, multisig_threshold],
        )
        exec_txn = await account.execute(
            calls=add_secp256r1_call,
            max_fee=10**17,
        )
        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    transfer_amount = 123
    block = await devnet_client.get_block()
    block_timestamp = block.timestamp

    out_ex = OutsideExecution(
        calls=[get_transfer_call(devnet_account.address, transfer_amount)],
        execute_before=block_timestamp + 3600,
        execute_after=block_timestamp - 3600)

    balance_before = await account.get_balance(FEE_CONTRACT_ADDRESS)
    caller_balance_before = await devnet_account.get_balance(
        FEE_CONTRACT_ADDRESS)
    await validate_outside_nonce(devnet_client, account.address, 0, 1)

    if multisig_threshold == 2 or second_signer_type is None:
        out_ex.sign_stark(account.address, stark_privk)
    out_ex.sign_ecc(account.address, secp256r1_keypair[0], second_signer_type)

    tx = await devnet_account.execute(
        out_ex.prepare_call(account.address),
        max_fee=10**17,
    )
    receipt = await devnet_client.wait_for_tx(tx.transaction_hash)

    balance_after = await account.get_balance(FEE_CONTRACT_ADDRESS)
    caller_balance_after = await devnet_account.get_balance(
        FEE_CONTRACT_ADDRESS)
    await validate_outside_nonce(devnet_client, account.address, 0, 0)

    assert balance_before == balance_after + transfer_amount, "wrong balance"
    assert (caller_balance_before == caller_balance_after - transfer_amount +
            receipt.actual_fee.amount), "wrong caller balance"


@pytest.mark.asyncio
async def test_outside_execution_interface(init_starknet, account_deployer):
    _, devnet_client, _ = init_starknet

    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account

    res = await devnet_client.call_contract(
        Call(
            to_addr=account.address,
            selector=get_selector_from_name("supports_interface"),
            calldata=[
                0x1d1144bb2138366ff28d8e9ab57456b1d332ac42196230c3a602003c89872
            ],
        ), )
    assert res[0] == 1, "interface not supported"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "invalid_params",
        "expected_error",
    ],
    [
        (dict(execute_after=time.time() + 500), "INVALID_TIMESTAMP"),
        (dict(execute_before=time.time() - 500), "INVALID_TIMESTAMP"),
        (dict(caller=0x1), "INVALID_CALLER"),
    ],
    ids=[
        "execute_time_in_future",
        "execute_time_in_past",
        "different_caller",
    ],
)
async def test_outside_execution_with_invalid_params(init_starknet,
                                                     account_deployer,
                                                     invalid_params,
                                                     expected_error):
    _, devnet_client, devnet_account = init_starknet

    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account

    out_ex = OutsideExecution(**invalid_params)

    out_ex.sign_stark(account.address, stark_privk)

    with pytest.raises(TransactionRevertedError,
                       match=encode_string_as_hex(expected_error)):
        tx = await devnet_account.execute(
            out_ex.prepare_call(account.address),
            max_fee=10**17,
        )
        await devnet_client.wait_for_tx(tx.transaction_hash)


@pytest.mark.asyncio
async def test_outside_execution_nonce_reuse(init_starknet, account_deployer):
    _, devnet_client, devnet_account = init_starknet

    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account

    block = await devnet_client.get_block()
    block_timestamp = block.timestamp

    out_ex1 = OutsideExecution(
        calls=[get_transfer_call(devnet_account.address, 1)],
        nonce=123,
        execute_before=block_timestamp + 3600,
        execute_after=block_timestamp - 3600)
    out_ex1.sign_stark(account.address, stark_privk)

    tx = await devnet_account.execute(
        out_ex1.prepare_call(account.address),
        max_fee=10**17,
    )
    await devnet_client.wait_for_tx(tx.transaction_hash)

    out_ex2 = OutsideExecution(
        calls=[get_transfer_call(devnet_account.address, 2)],
        nonce=123,
        execute_before=block_timestamp + 3600,
        execute_after=block_timestamp - 3600)
    out_ex2.sign_stark(account.address, stark_privk)

    with pytest.raises(TransactionRevertedError,
                       match=encode_string_as_hex("INVALID_NONCE")):
        tx = await devnet_account.execute(
            out_ex2.prepare_call(account.address),
            max_fee=10**17,
        )
        await devnet_client.wait_for_tx(tx.transaction_hash)


@pytest.mark.asyncio
async def test_outside_execution_empty_sig(init_starknet, account_deployer):
    _, devnet_client, devnet_account = init_starknet

    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account
    block = await devnet_client.get_block()
    block_timestamp = block.timestamp

    out_ex = OutsideExecution(
        calls=[get_transfer_call(devnet_account.address, 1)],
        execute_before=block_timestamp + 3600,
        execute_after=block_timestamp - 3600,
    )

    with pytest.raises(TransactionRevertedError,
                       match=encode_string_as_hex("INVALID_SIG")):
        tx = await devnet_account.execute(
            out_ex.prepare_call(account.address),
            max_fee=10**17,
        )
        await devnet_client.wait_for_tx(tx.transaction_hash)


@pytest.mark.asyncio
async def test_outside_execution_invalid_sig(init_starknet, account_deployer):
    _, devnet_client, devnet_account = init_starknet

    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account
    block = await devnet_client.get_block()
    block_timestamp = block.timestamp

    out_ex = OutsideExecution(
        calls=[get_transfer_call(devnet_account.address, 1)],
        execute_before=block_timestamp + 3600,
        execute_after=block_timestamp - 3600,
    )
    out_ex.sign_stark(account.address, stark_privk)
    out_ex.sig[1] += 1

    with pytest.raises(TransactionRevertedError,
                       match=encode_string_as_hex("INVALID_SIG")):
        tx = await devnet_account.execute(
            out_ex.prepare_call(account.address),
            max_fee=10**17,
        )
        await devnet_client.wait_for_tx(tx.transaction_hash)


@pytest.mark.asyncio
async def test_outside_execution_self_call(init_starknet, account_deployer):
    _, devnet_client, devnet_account = init_starknet

    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account
    block = await devnet_client.get_block()
    block_timestamp = block.timestamp

    out_ex = OutsideExecution(
        calls=[
            Call(
                to_addr=account.address,
                selector=get_selector_from_name("get_version"),
                calldata=[],
            )
        ],
        execute_before=block_timestamp + 3600,
        execute_after=block_timestamp - 3600,
    )
    out_ex.sign_stark(account.address, stark_privk)

    with pytest.raises(TransactionRevertedError,
                       match=encode_string_as_hex("SELF_CALL")):
        tx = await devnet_account.execute(
            out_ex.prepare_call(account.address),
            max_fee=10**17,
        )
        await devnet_client.wait_for_tx(tx.transaction_hash)
