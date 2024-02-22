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
from starknet_py.constants import FEE_CONTRACT_ADDRESS
from starknet_py.hash.casm_class_hash import compute_casm_class_hash
from starknet_py.hash.class_hash import compute_class_hash
from starknet_py.hash.sierra_class_hash import compute_sierra_class_hash
from starknet_py.hash.utils import compute_hash_on_elements
from starknet_py.net.account.account import AccountTransaction, Account, KeyPair
from starknet_py.net.client_models import (
    Call,
    TransactionExecutionStatus,
    TransactionReceipt,
)
from starknet_py.net.full_node_client import FullNodeClient
from starknet_py.hash.address import compute_address
from starknet_py.hash.selector import get_selector_from_name
from starknet_py.hash.transaction import compute_deploy_account_transaction_hash
from starknet_py.hash.utils import message_signature, private_to_stark_key
from starknet_py.net.schemas.gateway import (
    CasmClassSchema,
    ContractClassSchema,
    SierraCompiledContractSchema,
)
from starknet_py.net.models.chains import StarknetChainId
from starknet_py.net.models.transaction import DeployAccount

STARK_SIGNER_TYPE = 1
SECP256R1_SIGNER_TYPE = 2


async def declare(
    client: FullNodeClient,
    account: Account,
    casm_path: str,
    sierra_path: str,
    retries=5,
):
    with open(casm_path, "r") as f:
        casm_content = f.read()

    with open(sierra_path, "r") as f:
        sierra_content = f.read()

    casm_chash = compute_casm_class_hash(CasmClassSchema().loads(casm_content))
    sierra_chash = compute_sierra_class_hash(
        SierraCompiledContractSchema().loads(sierra_content, unknown="exclude")
    )
    declare_signed_txn = await account.sign_declare_v2_transaction(
        compiled_contract=sierra_content,
        compiled_class_hash=casm_chash,
        auto_estimate=True,
    )
    tries = 1
    while True:
        try:
            decl = await client.declare(declare_signed_txn)
            await client.wait_for_tx(decl.transaction_hash)
            break
        except Exception as e:
            if tries < retries:
                tries += 1
                time.sleep(5)
            else:
                print(f"Failed declaring class hash: {hex(sierra_chash)}")
                raise e

    return decl


def to_uint256(a):
    """Takes in value, returns uint256-ish tuple."""
    return (a & ((1 << 128) - 1), a >> 128)


def create_stark_signer(stark_privk: int, mock_est_fee=False):
    def sign_txn(txn: AccountTransaction):
        if not mock_est_fee or txn.version < 2**128:
            return [
                STARK_SIGNER_TYPE,
                *message_signature(
                    txn.calculate_hash(StarknetChainId.TESTNET),
                    stark_privk,
                ),
            ]
        else:
            return [STARK_SIGNER_TYPE, 0, 0]

    return namedtuple("StarkSigner", ["sign_transaction"])(lambda txn: sign_txn(txn))


def generate_secp256r1_keypair():
    ecc_key = ec.generate_private_key(ec.SECP256R1())
    pk_x_uint256 = to_uint256(ecc_key.public_key().public_numbers().x)
    pk_y_uint256 = to_uint256(ecc_key.public_key().public_numbers().y)

    return ecc_key, (pk_x_uint256, pk_y_uint256)


def create_secp256r1_signer(
    ecc_key: ec.EllipticCurvePrivateKey, legacy=False, mock_est_fee=False
):
    def sign_txn(txn: AccountTransaction):
        if mock_est_fee and txn.version >= 2**128:
            return [
                *(
                    [
                        SECP256R1_SIGNER_TYPE,
                        *[0, 0],
                        *[0, 0],
                    ]  # *pk_x_uint256, *pk_y_uint256]
                    if legacy is False
                    else []
                ),
                *[0, 0],
                *[0, 0],  # *to_uint256(r), *to_uint256(s)
            ]

        txn_hash = txn.calculate_hash(StarknetChainId.TESTNET)
        hash_bytes = txn_hash.to_bytes(
            (txn_hash.bit_length() + 7) // 8, byteorder="big", signed=False
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
            *(
                [SECP256R1_SIGNER_TYPE, *pk_x_uint256, *pk_y_uint256]
                if legacy is False
                else []
            ),
            *to_uint256(r),
            *to_uint256(s),
        ]

    return namedtuple("Secp256r1Signer", ["sign_transaction"])(
        lambda txn: sign_txn(txn)
    )


def default_deployment_signer(
    account_chash: int,
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
    secp256r1_signer = [0, 0, 0, 0] if secp256r1_signer is None else secp256r1_signer
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
    aux_hash = poseidon_hash_many(
        [
            account_chash,
            strong_signer_type,
            *secp256r1_signer,
            multisig_threshold,
            withdrawal_limit_low,
            eth_fee_rate,
            stark_fee_rate,
            StarknetChainId.TESTNET,
        ]
    )
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


async def account_deployer(
    client,
    ops_account,
    base_account_chash,
    account_chash,
    new_account_transfer_amount,
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
    stark_pubk = (
        stark_pub_key_override
        if stark_pub_key_override is not None
        else stark_keypair.public_key
    )
    ctor_calldata = [stark_pubk]
    account_address = compute_address(
        class_hash=base_account_chash,
        salt=stark_pubk,
        constructor_calldata=ctor_calldata,
    )
    print("Account address: ", hex(account_address))
    #        resp = requests.post(f"{devnet_url}/mint",
    #                      timeout=1000,
    #                      json={
    #                          "address": hex(account_address),
    #                          "amount": 10 * 10**18,
    #                      })
    exec = await ops_account.execute(
        Call(
            to_addr=int(FEE_CONTRACT_ADDRESS, 16),
            selector=get_selector_from_name("transfer"),
            calldata=[
                account_address,
                new_account_transfer_amount,
                0,
            ],
        ),
        auto_estimate=True,
    )
    await client.wait_for_tx(exec.transaction_hash)
    strong_signer_type = (
        0 if secp256r1_pubk in [None, [0, 0, 0, 0]] else 5 if is_webauthn else 2
    )

    if not erc20_address_to_transfer is None:
        exec = await ops_account.execute(
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
        await client.wait_for_tx(exec.transaction_hash)

    if deploy_signer is None:
        deploy_signer = namedtuple("_DeploySigner", ["sign_transaction"])(
            lambda depl_account: default_deployment_signer(
                account_chash,
                stark_keypair,
                depl_account,
                account_address,
                strong_signer_type,
                secp256r1_pubk or [0, 0, 0, 0],
                multisig_thresh,
                withdrawal_limit_low,
                eth_fee_rate,
                stark_fee_rate,
            )
        )
    deployer_account = Account(
        client=client,
        address=account_address,
        signer=deploy_signer,
    )

    signed_account_depl = await deployer_account.sign_deploy_account_v1_transaction(
        class_hash=base_account_chash,
        contract_address_salt=stark_pubk,
        constructor_calldata=ctor_calldata,
        auto_estimate=True,
    )
    account_depl = await client.deploy_account(signed_account_depl)
    await client.wait_for_tx(account_depl.transaction_hash)

    return (
        Account(
            client=client,
            address=account_address,
            key_pair=stark_keypair,
            chain=StarknetChainId.TESTNET,
        ),
        account_depl.transaction_hash,
    )


def compute_myswap_cl_to_usdc_price(
    target_rate_usdc_for_token, token_decimal, is_usdc_token0
):
    # USDC decimals == 6
    # Target rate is in [USDC/TOKEN] units so amount[TOKEN] * target_rate[USDC/TOKEN] = amount[USDC]
    # Output rate is expected to be TOKEN A in terms of TOKEN B i.e. [TOKEN_B / TOKEN_A]  where addr(TOKEN A) < addr(TOKEN B)
    output_rate = (target_rate_usdc_for_token * (10**6 / 10**token_decimal)) ** (
        -1 if is_usdc_token0 else 1
    ) * (2**96)
    return int(output_rate)


def compute_v3_txn_hash(
    prefix,
    version,
    address,
    tip,
    l1_resource_bound_max_amount,
    l1_resource_bound_max_price,
    l2_resource_bound_max_amount,
    l2_resource_bound_max_price,
    paymaster_data,
    chain_id,
    nonce,
    nonce_da,
    fee_da,
    reserved,
    account_deployment_data,
    calldata,
):
    encoded_prefix = int.from_bytes(prefix.encode("ascii"), "big")
    l1_res_bound_flat = (
        (int.from_bytes(b"L1_GAS", "big") << 192)
        + (l1_resource_bound_max_amount << 128)
        + l1_resource_bound_max_price
    )
    l2_res_bound_flat = (
        (int.from_bytes(b"L2_GAS", "big") << 192)
        + (l2_resource_bound_max_amount << 128)
        + l2_resource_bound_max_price
    )
    fee_h = poseidon_hash_many([tip, l1_res_bound_flat, l2_res_bound_flat])

    data_to_hash = [
        encoded_prefix,
        version,
        address,
        fee_h,
        poseidon_hash_many(paymaster_data),
        chain_id,
        nonce,
        (nonce_da << 32) + fee_da,
        # reserved,  - not used
        poseidon_hash_many(account_deployment_data),
        poseidon_hash_many(calldata),
    ]
    return poseidon_hash_many(data_to_hash)


async def execute_calls(account: Account, calls: Union[Call, List[Call]], max_fee=None):
    if max_fee is None:
        invoke_txn = await account.sign_invoke_v1_transaction(
            calls, max_fee=int(0.1 * 10**18)
        )
        invoke_est_fee = await account.sign_for_fee_estimate(invoke_txn)
        est_fee = await account.client.estimate_fee(invoke_est_fee)
        max_fee = est_fee.overall_fee + 25000 * est_fee.gas_price
    exec = await account.execute(
        calls,
        # cairo_version=cairo_version,
        max_fee=max_fee,
    )
    receipt = await account.client.wait_for_tx(exec.transaction_hash)
    assert receipt.execution_status == TransactionExecutionStatus.SUCCEEDED
    return receipt
