from e2e.utils.utils import *
from e2e.utils.utils_v2 import *
from e2e.utils.fixtures import *
from e2e.utils.typed_data import TypedDataR1

import base64
import json
import pytest
import random

from starknet_py.constants import FEE_CONTRACT_ADDRESS
from starknet_py.net.client_models import Call
from starknet_py.net.full_node_client import FullNodeClient
from starknet_py.hash.selector import get_selector_from_name
from starknet_py.utils.iterable import ensure_iterable
from starknet_py.transaction_errors import TransactionRevertedError
from starknet_py.net.account.account import (
    Account,
    _execute_payload_serializer_v2,
    _parse_calls_v2,
)


@pytest.mark.asyncio
async def test_get_required_signer(
    init_starknet,
    account_deployer,
    init_pricing_contract,
    clean_token_config,
    mock_usdc_threshold_token,
    set_and_assert_high_threshold,
    assert_required_signer_of_bypass_call,
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

    # for simplicity, we set stark token value to be just like eth
    await set_price(
        compute_myswap_cl_pool_key(STRK_ADDRESS, USDC_ADDR, 500), 86400,
        compute_myswap_cl_to_usdc_price(target_rate_usdc_for_token=1000 // 1,
                                        token_decimal=18,
                                        is_usdc_token0=False))

    # start with a stored rate lower than actual price service rate
    await assert_required_signer_of_bypass_call(account,
                                                REQUIRED_SIGNER_STARK,
                                                amount=0,
                                                fee=0)
    await assert_required_signer_of_bypass_call(account,
                                                REQUIRED_SIGNER_STRONG,
                                                amount=10**17,
                                                fee=10**17)
    await assert_required_signer_of_bypass_call(account,
                                                REQUIRED_SIGNER_MULTISIG,
                                                amount=2 * 10**17,
                                                fee=2 * 10**17)

    await set_price(
        compute_myswap_cl_pool_key(int(FEE_CONTRACT_ADDRESS, 16), USDC_ADDR,
                                   500), 86400,
        compute_myswap_cl_to_usdc_price(target_rate_usdc_for_token=10 // 1,
                                        token_decimal=18,
                                        is_usdc_token0=False))
    # for simplicity, we set stark token value to be just like eth
    await set_price(
        compute_myswap_cl_pool_key(STRK_ADDRESS, USDC_ADDR, 500), 86400,
        compute_myswap_cl_to_usdc_price(target_rate_usdc_for_token=10 // 1,
                                        token_decimal=18,
                                        is_usdc_token0=False))

    # now the stored rate is higher than the price service
    await assert_required_signer_of_bypass_call(account,
                                                REQUIRED_SIGNER_STARK,
                                                amount=0,
                                                fee=0)
    await assert_required_signer_of_bypass_call(account,
                                                REQUIRED_SIGNER_STRONG,
                                                amount=10**18,
                                                fee=10**18)
    await assert_required_signer_of_bypass_call(account,
                                                REQUIRED_SIGNER_MULTISIG,
                                                amount=5 * 10**18,
                                                fee=3 * 10**18)


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
        ("initializer", 1, "INVALID_INITIALIZATION"),
        ("initializer_from_factory", 1 + 13, "ALREADY_INITIALIZED"),
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
        self.typed_data = TypedDataR1(
            {
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
            }, "Account.execute_from_outside", "2")

    def get_hash(self, account_address):
        message = {
            "Caller": self.caller,
            "Nonce": self.nonce,
            "Execute After": self.execute_after,
            "Execute Before": self.execute_before,
            "Calls": parse_calls_for_typed_data(ensure_iterable(self.calls))
        }
        return self.typed_data.get_hash(message, account_address,
                                        "OutsideExecution")

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

    if multisig_threshold == 2 or second_signer_type == None:
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
        execute_after=block_timestamp - 3600)

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
        execute_after=block_timestamp - 3600)
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

    out_ex = OutsideExecution(calls=[
        Call(
            to_addr=account.address,
            selector=get_selector_from_name("get_version"),
            calldata=[],
        )
    ],
                              execute_before=block_timestamp + 3600,
                              execute_after=block_timestamp - 3600)
    out_ex.sign_stark(account.address, stark_privk)

    with pytest.raises(TransactionRevertedError,
                       match=encode_string_as_hex("SELF_CALL")):
        tx = await devnet_account.execute(
            out_ex.prepare_call(account.address),
            max_fee=10**17,
        )
        await devnet_client.wait_for_tx(tx.transaction_hash)
