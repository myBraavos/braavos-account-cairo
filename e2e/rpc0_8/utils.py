from pathlib import Path
from typing import Optional, cast, Dict, List
from functools import reduce
from cryptography.hazmat.primitives.asymmetric import ec
from poseidon_py.poseidon_hash import poseidon_hash_many
from starknet_py.cairo.felt import encode_shortstring
from starknet_py.common import int_from_bytes, create_sierra_compiled_contract
from starknet_py.hash.casm_class_hash import compute_casm_class_hash
from starknet_py.hash.sierra_class_hash import compute_sierra_class_hash
from starknet_py.hash.utils import message_signature
from starknet_py.net.account.account import _parse_calls
from starknet_py.net.client_models import ResourceBounds, SierraContractClass, Call
from starknet_py.net.schemas.rpc.contract import (
    CasmClassSchema,
    SierraCompiledContractSchema,
)
from starknet_py.hash.selector import get_selector_from_name
from typing import Callable
from dataclasses import dataclass
from enum import IntEnum
import aiohttp
import asyncio

DEVNET_CHAIN_ID = int_from_bytes(b"SN_SEPOLIA")
STRK_CONTRACT = 0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d

L1_GAS_ENCODED = encode_shortstring("L1_GAS")
L2_GAS_ENCODED = encode_shortstring("L2_GAS")
L1_DATA_ENCODED = encode_shortstring("L1_DATA")

DEVNET_ACCOUNT_ADDRESS = 0x64b48806902a367c8598f4f95c305e8c1a1acba5f082d294a43793113115691
DEVNET_ACCOUNT_PRIVK = 0x71d7bb07b9a64f6f78ac4c816aff4da9
SN_DEVNET_URL = "http://127.0.0.1:5051/rpc"


@dataclass
class ResourceBoundsMapping:
    l1_gas: ResourceBounds
    l1_data_gas: ResourceBounds
    l2_gas: ResourceBounds

    @staticmethod
    def init_with_zeros():
        return ResourceBoundsMapping(
            l1_gas=ResourceBounds.init_with_zeros(),
            l1_data_gas=ResourceBounds.init_with_zeros(),
            l2_gas=ResourceBounds.init_with_zeros(),
        )


class TransactionHashPrefix(IntEnum):
    DECLARE = int_from_bytes(b"declare")
    DEPLOY = int_from_bytes(b"deploy")
    DEPLOY_ACCOUNT = int_from_bytes(b"deploy_account")
    INVOKE = int_from_bytes(b"invoke")
    L1_HANDLER = int_from_bytes(b"l1_handler")


@dataclass
class CommonTransactionV3Fields:
    tx_prefix: TransactionHashPrefix
    version: int
    address: int
    tip: int
    resource_bounds: ResourceBoundsMapping
    paymaster_data: list
    chain_id: int
    nonce: int
    nonce_data_availability_mode: int = 0
    fee_data_availability_mode: int = 0

    def compute_resource_bounds_for_fee(self) -> list:
        l1_gas_bounds = ((L1_GAS_ENCODED << (128 + 64)) +
                         (self.resource_bounds.l1_gas.max_amount << 128) +
                         self.resource_bounds.l1_gas.max_price_per_unit)

        l2_gas_bounds = ((L2_GAS_ENCODED << (128 + 64)) +
                         (self.resource_bounds.l2_gas.max_amount << 128) +
                         self.resource_bounds.l2_gas.max_price_per_unit)

        l1_data_gas_bounds = (
            (L1_DATA_ENCODED << (128 + 64)) +
            (self.resource_bounds.l1_data_gas.max_amount << 128) +
            self.resource_bounds.l1_data_gas.max_price_per_unit)

        return [l1_gas_bounds, l2_gas_bounds, l1_data_gas_bounds]

    def get_data_availability_modes(self) -> int:
        return (self.nonce_data_availability_mode <<
                32) + self.fee_data_availability_mode

    def compute_common_tx_fields(self):
        return [
            self.tx_prefix,
            self.version,
            self.address,
            poseidon_hash_many(
                [self.tip, *self.compute_resource_bounds_for_fee()]),
            poseidon_hash_many(self.paymaster_data),
            self.chain_id,
            self.nonce,
            self.get_data_availability_modes(),
        ]


def get_contract_str(artifact_prefix: str) -> str:
    sierra_artifact = Path(f"{artifact_prefix}.contract_class.json")
    casm_artifact = Path(f"{artifact_prefix}.compiled_contract_class.json")
    return sierra_artifact.read_text(), casm_artifact.read_text()


def compute_declare_v3_transaction_hash(
    *,
    contract_class: Optional[SierraContractClass] = None,
    class_hash: Optional[int] = None,
    account_deployment_data: list,
    compiled_class_hash: int,
    common_fields: CommonTransactionV3Fields,
) -> int:
    if class_hash is None:
        if contract_class is None:
            raise ValueError(
                "Either contract_class or class_hash is required.")
        class_hash = compute_sierra_class_hash(contract_class)

    return poseidon_hash_many([
        *common_fields.compute_common_tx_fields(),
        poseidon_hash_many(account_deployment_data),
        class_hash,
        compiled_class_hash,
    ])


async def declare_v3_direct_rpc(
    address: int,
    stark_private_key: int,
    sierra_content: str,
    casm_content: str,
    resource_bounds: ResourceBoundsMapping,
) -> int:
    nonce = await get_nonce_rpc(address)

    common_fields = CommonTransactionV3Fields(
        tx_prefix=TransactionHashPrefix.DECLARE,
        version=3,
        address=address,
        tip=0,
        resource_bounds=resource_bounds,
        paymaster_data=[],
        chain_id=DEVNET_CHAIN_ID,
        nonce=nonce)

    casm_class_hash = compute_casm_class_hash(
        CasmClassSchema().loads(casm_content))
    contract_class = create_sierra_compiled_contract(
        compiled_contract=sierra_content)

    tx_hash = compute_declare_v3_transaction_hash(
        contract_class=contract_class.convert_to_sierra_contract_class(),
        account_deployment_data=[],
        compiled_class_hash=casm_class_hash,
        common_fields=common_fields)

    signature = message_signature(tx_hash, stark_private_key)

    declare_tx = {
        "type":
        "DECLARE",
        "version":
        "0x3",
        "compiled_class_hash":
        hex(casm_class_hash),
        "contract_class":
        cast(Dict,
             SierraCompiledContractSchema().dump(obj=contract_class)),
        "sender_address":
        hex(address),
        "resource_bounds": {
            "l1_gas": {
                "max_amount":
                hex(resource_bounds.l1_gas.max_amount),
                "max_price_per_unit":
                hex(resource_bounds.l1_gas.max_price_per_unit),
            },
            "l1_data_gas": {
                "max_amount":
                hex(resource_bounds.l1_data_gas.max_amount),
                "max_price_per_unit":
                hex(resource_bounds.l1_data_gas.max_price_per_unit),
            },
            "l2_gas": {
                "max_amount":
                hex(resource_bounds.l2_gas.max_amount),
                "max_price_per_unit":
                hex(resource_bounds.l2_gas.max_price_per_unit),
            },
        },
        "tip":
        "0x0",
        "nonce_data_availability_mode":
        "L1",
        "fee_data_availability_mode":
        "L1",
        "paymaster_data": [],
        "nonce":
        hex(nonce),
        "signature": [hex(sig) for sig in signature],
        "account_deployment_data": [],
    }

    result = await send_transaction_rpc("starknet_addDeclareTransaction",
                                        {"declare_transaction": declare_tx})
    await wait_for_tx_rpc(tx_hash)
    return int(result["class_hash"], 16)


def compute_deploy_account_v3_transaction_hash(
    *,
    class_hash: int,
    constructor_calldata: list,
    contract_address_salt: int,
    common_fields: CommonTransactionV3Fields,
) -> int:
    return poseidon_hash_many([
        *common_fields.compute_common_tx_fields(),
        poseidon_hash_many(constructor_calldata),
        class_hash,
        contract_address_salt,
    ])


async def deploy_account_v3_direct_rpc(
    address: int,
    sign_function: Callable,
    stark_private_key: int,
    class_hash: int,
    constructor_calldata: list,
    contract_address_salt: int,
    resource_bounds: ResourceBoundsMapping,
) -> int:
    nonce = 0

    deploy_account_tx = {
        "common_fields":
        CommonTransactionV3Fields(
            tx_prefix=TransactionHashPrefix.DEPLOY_ACCOUNT,
            version=3,
            address=address,
            tip=0,
            resource_bounds=resource_bounds,
            paymaster_data=[],
            chain_id=DEVNET_CHAIN_ID,
            nonce=nonce,
            nonce_data_availability_mode=0,
            fee_data_availability_mode=0,
        ),
        "class_hash":
        class_hash,
        "contract_address_salt":
        contract_address_salt,
        "constructor_calldata": (constructor_calldata or []),
        "signature": [],
    }

    signature = sign_function(deploy_txn=deploy_account_tx)

    deploy_tx = {
        "type": "DEPLOY_ACCOUNT",
        "version": "0x3",
        "class_hash": hex(class_hash),
        "contract_address_salt": hex(contract_address_salt),
        "constructor_calldata": ([hex(c) for c in constructor_calldata] or []),
        "resource_bounds": {
            "l1_gas": {
                "max_amount":
                hex(resource_bounds.l1_gas.max_amount),
                "max_price_per_unit":
                hex(resource_bounds.l1_gas.max_price_per_unit),
            },
            "l1_data_gas": {
                "max_amount":
                hex(resource_bounds.l1_data_gas.max_amount),
                "max_price_per_unit":
                hex(resource_bounds.l1_data_gas.max_price_per_unit),
            },
            "l2_gas": {
                "max_amount":
                hex(resource_bounds.l2_gas.max_amount),
                "max_price_per_unit":
                hex(resource_bounds.l2_gas.max_price_per_unit),
            },
        },
        "tip": "0x0",
        "nonce_data_availability_mode": "L1",
        "fee_data_availability_mode": "L1",
        "paymaster_data": [],
        "nonce": hex(nonce),
        "signature": [hex(sig) for sig in signature],
    }

    response = await send_transaction_rpc(
        "starknet_addDeployAccountTransaction",
        {"deploy_account_transaction": deploy_tx})
    return response


async def invoke_v3_direct_rpc(
    account_address: int,
    account_private_key: int,
    calls: List[Call],
    resource_bounds: ResourceBoundsMapping,
    cairo_version: int = 1,
) -> int:

    nonce = await get_nonce_rpc(account_address)

    common_fields = CommonTransactionV3Fields(
        tx_prefix=TransactionHashPrefix.INVOKE,
        version=3,
        address=account_address,
        tip=0,
        resource_bounds=resource_bounds,
        paymaster_data=[],
        chain_id=DEVNET_CHAIN_ID,
        nonce=nonce)

    calldata = _parse_calls(cairo_version, calls)

    tx_hash = poseidon_hash_many([
        *common_fields.compute_common_tx_fields(),
        poseidon_hash_many([]),
        poseidon_hash_many(calldata),
    ])

    signature = message_signature(tx_hash, account_private_key)
    print(f"tx_hash: {hex(tx_hash)}, {signature}, {calldata}")

    invoke_tx = {
        "type": "INVOKE",
        "version": "0x3",
        "sender_address": hex(account_address),
        "calldata": [hex(x) for x in calldata],
        "resource_bounds": {
            "l1_gas": {
                "max_amount":
                hex(resource_bounds.l1_gas.max_amount),
                "max_price_per_unit":
                hex(resource_bounds.l1_gas.max_price_per_unit),
            },
            "l1_data_gas": {
                "max_amount":
                hex(resource_bounds.l1_data_gas.max_amount),
                "max_price_per_unit":
                hex(resource_bounds.l1_data_gas.max_price_per_unit),
            },
            "l2_gas": {
                "max_amount":
                hex(resource_bounds.l2_gas.max_amount),
                "max_price_per_unit":
                hex(resource_bounds.l2_gas.max_price_per_unit),
            }
        },
        "tip": "0x0",
        "nonce_data_availability_mode": "L1",
        "fee_data_availability_mode": "L1",
        "paymaster_data": [],
        "nonce": hex(nonce),
        "signature": [hex(sig) for sig in signature],
        "account_deployment_data": [],
    }

    await send_transaction_rpc("starknet_addInvokeTransaction",
                               {"invoke_transaction": invoke_tx})
    await wait_for_tx_rpc(tx_hash)
    return tx_hash


def get_generic_resource_bounds():
    return ResourceBoundsMapping(
        l1_gas=ResourceBounds(max_amount=int(1e6),
                              max_price_per_unit=int(100_000_000_000)),
        l1_data_gas=ResourceBounds(max_amount=int(1e6),
                                   max_price_per_unit=int(100_000_000_000)),
        l2_gas=ResourceBounds(max_amount=int(1e7),
                              max_price_per_unit=int(100_000_000_000)),
    )


async def fund_account(address: int, amount: int):
    resource_bounds = get_generic_resource_bounds()

    tx_hash = await invoke_v3_direct_rpc(
        account_address=DEVNET_ACCOUNT_ADDRESS,
        account_private_key=DEVNET_ACCOUNT_PRIVK,
        cairo_version=0,
        calls=[
            Call(
                to_addr=STRK_CONTRACT,
                selector=get_selector_from_name("transfer"),
                calldata=[address, amount, 0],
            ),
        ],
        resource_bounds=resource_bounds,
    )

    print(f"Transfer transaction hash: {tx_hash}")


def to_uint256(a):
    return (a & ((1 << 128) - 1), a >> 128)


def generate_secp256r1_keypair():
    ecc_key = ec.generate_private_key(ec.SECP256R1())
    pk_x_uint256 = to_uint256(ecc_key.public_key().public_numbers().x)
    pk_y_uint256 = to_uint256(ecc_key.public_key().public_numbers().y)

    return ecc_key, (pk_x_uint256, pk_y_uint256)


def flatten_seq(x):
    return reduce(
        lambda target, elem: (target + flatten_seq(elem))
        if hasattr(elem, "__iter__") and not isinstance(elem, str) else
        (target + [elem]
         if isinstance(elem, int) else target + [int(elem, 16)]),
        x,
        [],
    )


async def get_nonce_rpc(address: int) -> int:
    payload = {
        "jsonrpc": "2.0",
        "method": "starknet_getNonce",
        "params": {
            "block_id": "latest",
            "contract_address": hex(address)
        },
        "id": 1
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(SN_DEVNET_URL, json=payload) as response:
            result = await response.json()

            if "error" in result:
                raise Exception(f"RPC error: {result['error']}")

            return int(result["result"], 16)


async def wait_for_tx_rpc(tx_hash: int) -> None:
    async with aiohttp.ClientSession() as session:
        while True:
            status_payload = {
                "jsonrpc": "2.0",
                "method": "starknet_getTransactionReceipt",
                "params": {
                    "transaction_hash": hex(tx_hash)
                },
                "id": 1
            }

            async with session.post(SN_DEVNET_URL,
                                    json=status_payload) as response:
                status_result = await response.json()

                if "error" not in status_result and status_result["result"][
                        "finality_status"] == "ACCEPTED_ON_L2":
                    break

            await asyncio.sleep(0.1)


async def send_transaction_rpc(method: str, tx_payload: dict) -> dict:
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": tx_payload,
        "id": 1
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(SN_DEVNET_URL, json=payload) as response:
            result = await response.json()

            if "error" in result:
                raise Exception(f"RPC error: {result['error']}")

            return result["result"]


async def call_contract_rpc(call: Call, block_id: str = "latest") -> List[int]:
    payload = {
        "jsonrpc": "2.0",
        "method": "starknet_call",
        "params": {
            "request": {
                "contract_address": hex(call.to_addr),
                "entry_point_selector": hex(call.selector),
                "calldata": [hex(x) for x in (call.calldata or [])],
            },
            "block_id": block_id
        },
        "id": 1
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(SN_DEVNET_URL, json=payload) as response:
            result = await response.json()
            if "error" in result:
                raise Exception(f"RPC error: {result['error']}")

            return [int(x, 16) for x in result["result"]]
