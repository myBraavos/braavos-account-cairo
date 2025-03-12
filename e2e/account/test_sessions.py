from e2e.utils.utils_v2 import *
from e2e.utils.fixtures import *
from e2e.utils.typed_data import OutsideExecution, get_test_call, CalldataValidation, AllowedMethod

import base64
import json
import pytest
import random

from starknet_py.constants import FEE_CONTRACT_ADDRESS
from starknet_py.net.client_models import Call
from starknet_py.net.full_node_client import FullNodeClient
from starknet_py.hash.selector import get_selector_from_name
from starknet_py.transaction_errors import TransactionRevertedError
from starknet_py.net.client_errors import ClientError
from starknet_py.net.account.account import Account


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "second_signer_type",
        "multisig_threshold",
        "withdrawal_limit_low",
        "withdrawal_limit_high",
    ],
    [
        (None, 0, 0, 0),
        (SECP256R1_SIGNER_TYPE, 0, 0, 0),
        (SECP256R1_SIGNER_TYPE, 0, 50 * USDC, 0),
        (SECP256R1_SIGNER_TYPE, 2, 0, 0),
        (SECP256R1_SIGNER_TYPE, 2, 50 * USDC, 0),
        (SECP256R1_SIGNER_TYPE, 2, 50 * USDC, 100 * USDC),
        (WEBAUTHN_SIGNER_TYPE, 0, 0, 0),
        (WEBAUTHN_SIGNER_TYPE, 0, 50 * USDC, 0),
        (WEBAUTHN_SIGNER_TYPE, 2, 0, 0),
        (WEBAUTHN_SIGNER_TYPE, 2, 50 * USDC, 0),
        (WEBAUTHN_SIGNER_TYPE, 2, 50 * USDC, 100 * USDC),
    ],
    ids=[
        "no_second_signer_no_multisig",
        "with_secp256r1_no_multisig",
        "with_secp256r1_no_multisig_dwl_low",
        "with_secp256r1_multisig",
        "with_secp256r1_multisig_dwl_low",
        "with_secp256r1_multisig_dwl_low_high",
        "with_webauthn_no_multisig",
        "with_webauthn_no_multisig_dwl_low",
        "with_webauthn_multisig",
        "with_webauthn_multisig_dwl_low",
        "with_webauthn_multisig_dwl_low_high",
    ],
)
@pytest.mark.parametrize("is_gas_sponsored_execution", [True, False])
@pytest.mark.parametrize("is_v3", [True, False])
@pytest.mark.parametrize("is_v2_typed_data", [False, True])
async def test_session_execution(init_starknet, account_deployer,
                                 setup_session_account_env, second_signer_type,
                                 withdrawal_limit_low, withdrawal_limit_high,
                                 multisig_threshold,
                                 is_gas_sponsored_execution, is_v3,
                                 is_v2_typed_data):
    _, devnet_client, devnet_account = init_starknet

    session_account, execute_session_call, session_request_builder, event_name, session_owner_identifier, destination_account = await setup_session_account_env(
        is_gas_sponsored_execution,
        second_signer_type,
        multisig_threshold,
        withdrawal_limit_low=withdrawal_limit_low,
        withdrawal_limit_high=withdrawal_limit_high)

    block = await devnet_client.get_block()
    block_timestamp = block.timestamp

    oe = session_request_builder(session_account,
                                 session_owner_identifier,
                                 block_timestamp + 3600,
                                 block_timestamp - 3600,
                                 is_v2_typed_data=is_v2_typed_data)
    balance_before = await destination_account.get_balance(FEE_CONTRACT_ADDRESS
                                                           )

    oe_call = oe.prepare_call([
        get_test_call(destination_account.address, 100),
        get_test_call(destination_account.address,
                      100,
                      function_name="approve",
                      token_address=STRK_ADDRESS)
    ], session_account.address)

    if not is_v3 and not is_gas_sponsored_execution:
        with pytest.raises((TransactionRevertedError, ClientError),
                           match=encode_string_as_hex("INVALID_TX_VERSION")):
            tx = await execute_session_call(oe_call, is_v3=False)
            await devnet_client.wait_for_tx(tx.transaction_hash)
        return

    tx = await execute_session_call(oe_call, is_v3=is_v3)
    receipt = await devnet_client.wait_for_tx(tx.transaction_hash)
    balance_after = await destination_account.get_balance(FEE_CONTRACT_ADDRESS)
    assert balance_after - balance_before == 100, "Wrong balance change"

    assert txn_receipt_contains_event(
        receipt,
        [
            get_selector_from_name(event_name),
            oe.get_hash(session_account.address)
        ],
        [
            session_owner_identifier, oe.execute_after, oe.execute_before,
            receipt.transaction_hash
        ],
        match_data=True,
    ) is True, "no execute session started event"
    # making sure that session context is cached after first transaction
    # and no need for more validation
    oe.sig = []
    balance_before = await destination_account.get_balance(FEE_CONTRACT_ADDRESS
                                                           )

    oe_call = oe.prepare_call([
        get_test_call(destination_account.address,
                      100,
                      function_name="approve",
                      token_address=STRK_ADDRESS),
        get_test_call(destination_account.address, 100)
    ], session_account.address)

    tx = await execute_session_call(oe_call, is_v3=is_v3)
    receipt = await devnet_client.wait_for_tx(tx.transaction_hash)
    balance_after = await destination_account.get_balance(FEE_CONTRACT_ADDRESS)
    assert balance_after - balance_before == 100, "Wrong balance change"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "second_signer_type",
        "multisig_threshold",
        "withdrawal_limit_low",
        "withdrawal_limit_high",
    ],
    [
        (None, 0, 0, 0),
        (SECP256R1_SIGNER_TYPE, 0, 0, 0),
        (SECP256R1_SIGNER_TYPE, 0, 50 * USDC, 0),
        (SECP256R1_SIGNER_TYPE, 2, 0, 0),
        (SECP256R1_SIGNER_TYPE, 2, 50 * USDC, 0),
        (SECP256R1_SIGNER_TYPE, 2, 50 * USDC, 100 * USDC),
        (WEBAUTHN_SIGNER_TYPE, 0, 0, 0),
        (WEBAUTHN_SIGNER_TYPE, 0, 50 * USDC, 0),
        (WEBAUTHN_SIGNER_TYPE, 2, 0, 0),
        (WEBAUTHN_SIGNER_TYPE, 2, 50 * USDC, 0),
        (WEBAUTHN_SIGNER_TYPE, 2, 50 * USDC, 100 * USDC),
    ],
    ids=[
        "no_second_signer_no_multisig",
        "with_secp256r1_no_multisig",
        "with_secp256r1_no_multisig_dwl_low",
        "with_secp256r1_multisig",
        "with_secp256r1_multisig_dwl_low",
        "with_secp256r1_multisig_dwl_low_high",
        "with_webauthn_no_multisig",
        "with_webauthn_no_multisig_dwl_low",
        "with_webauthn_multisig",
        "with_webauthn_multisig_dwl_low",
        "with_webauthn_multisig_dwl_low_high",
    ],
)
@pytest.mark.parametrize("is_gas_sponsored_execution", [True, False])
@pytest.mark.parametrize("is_v3", [True, False])
async def test_session_execution_with_bad_calldata(
        init_starknet, account_deployer, setup_session_account_env,
        second_signer_type, withdrawal_limit_low, withdrawal_limit_high,
        multisig_threshold, is_gas_sponsored_execution, is_v3):
    _, devnet_client, devnet_account = init_starknet

    session_account, execute_session_call, session_request_builder, event_name, session_owner_identifier, destination_account = await setup_session_account_env(
        is_gas_sponsored_execution,
        second_signer_type,
        multisig_threshold,
        withdrawal_limit_low=withdrawal_limit_low,
        withdrawal_limit_high=withdrawal_limit_high)

    block = await devnet_client.get_block()
    block_timestamp = block.timestamp

    oe = session_request_builder(
        session_account,
        session_owner_identifier,
        block_timestamp + 3600,
        block_timestamp - 3600,
        is_v2_typed_data=True,
        calls=[
            AllowedMethod(
                to_addr=STRK_ADDRESS,
                selector=get_selector_from_name("approve"),
                calldata_validations=[
                    # amount.low
                    CalldataValidation(offset=1, value=100),
                    # amount.high
                    CalldataValidation(offset=2, value=0),
                    # spender
                    CalldataValidation(offset=0,
                                       value=destination_account.address),
                ]),
            AllowedMethod(
                to_addr=STRK_ADDRESS,
                selector=get_selector_from_name("test0"),
                calldata_validations=[],
            ),
            AllowedMethod(
                to_addr=STRK_ADDRESS,
                selector=get_selector_from_name("test1"),
                calldata_validations=[],
            ),
            AllowedMethod(
                to_addr=int(FEE_CONTRACT_ADDRESS, 16),
                selector=get_selector_from_name("test2"),
                calldata_validations=[],
            ),
            AllowedMethod(
                to_addr=int(FEE_CONTRACT_ADDRESS, 16),
                selector=get_selector_from_name("transfer"),
                calldata_validations=[
                    # amount.low
                    CalldataValidation(offset=1, value=100),
                    # amount.high
                    CalldataValidation(offset=2, value=0),
                    # to
                    CalldataValidation(offset=0,
                                       value=destination_account.address),
                ],
            ),
            AllowedMethod(
                to_addr=int(FEE_CONTRACT_ADDRESS, 16),
                selector=get_selector_from_name("test3"),
                calldata_validations=[],
            ),
        ])

    if not is_v3 and not is_gas_sponsored_execution:
        return

    with pytest.raises((TransactionRevertedError, ClientError),
                       match=encode_string_as_hex("BAD_CALLDATA")):
        oe_call = oe.prepare_call([
            get_test_call(devnet_account.address, 100),
            get_test_call(devnet_account.address,
                          100,
                          function_name="approve",
                          token_address=STRK_ADDRESS)
        ], session_account.address)
        tx = await execute_session_call(oe_call)
        await devnet_client.wait_for_tx(tx.transaction_hash)

    with pytest.raises((TransactionRevertedError, ClientError),
                       match=encode_string_as_hex("BAD_CALLDATA")):
        oe_call = oe.prepare_call([
            get_test_call(destination_account.address, 1001),
            get_test_call(destination_account.address,
                          100,
                          function_name="approve",
                          token_address=STRK_ADDRESS)
        ], session_account.address)
        tx = await execute_session_call(oe_call)
        await devnet_client.wait_for_tx(tx.transaction_hash)


@pytest.mark.asyncio
@pytest.mark.parametrize("is_gas_sponsored_execution", [True, False])
@pytest.mark.parametrize("is_v3", [True, False])
async def test_session_execution_with_multiple_call_validations_on_same_method(
        init_starknet, account_deployer, setup_session_account_env,
        is_gas_sponsored_execution, is_v3):
    _, devnet_client, devnet_account = init_starknet

    session_account, execute_session_call, session_request_builder, _, session_owner_identifier, destination_account = await setup_session_account_env(
        is_gas_sponsored_execution, SECP256R1_SIGNER_TYPE, 0)

    block = await devnet_client.get_block()
    block_timestamp = block.timestamp

    oe = session_request_builder(
        session_account,
        session_owner_identifier,
        block_timestamp + 3600,
        block_timestamp - 3600,
        is_v2_typed_data=True,
        calls=[
            AllowedMethod(to_addr=STRK_ADDRESS,
                          selector=get_selector_from_name("approve"),
                          calldata_validations=[
                              CalldataValidation(
                                  offset=0, value=destination_account.address)
                          ]),
            AllowedMethod(to_addr=STRK_ADDRESS,
                          selector=get_selector_from_name("approve"),
                          calldata_validations=[
                              CalldataValidation(offset=0,
                                                 value=devnet_account.address)
                          ]),
            AllowedMethod(
                to_addr=STRK_ADDRESS,
                selector=get_selector_from_name("test0"),
                calldata_validations=[],
            ),
            AllowedMethod(
                to_addr=STRK_ADDRESS,
                selector=get_selector_from_name("test1"),
                calldata_validations=[],
            ),
            AllowedMethod(
                to_addr=int(FEE_CONTRACT_ADDRESS, 16),
                selector=get_selector_from_name("test2"),
                calldata_validations=[],
            ),
            AllowedMethod(
                to_addr=int(FEE_CONTRACT_ADDRESS, 16),
                selector=get_selector_from_name("transfer"),
                calldata_validations=[
                    # amount.low
                    CalldataValidation(offset=1, value=100),
                    # amount.high
                    CalldataValidation(offset=2, value=0),
                    # to
                    CalldataValidation(offset=0,
                                       value=destination_account.address),
                ],
            ),
            AllowedMethod(
                to_addr=int(FEE_CONTRACT_ADDRESS, 16),
                selector=get_selector_from_name("test3"),
                calldata_validations=[],
            ),
        ])

    if not is_v3 and not is_gas_sponsored_execution:
        return

    oe_call = oe.prepare_call([
        get_test_call(destination_account.address,
                      100,
                      function_name="approve",
                      token_address=STRK_ADDRESS),
        get_test_call(devnet_account.address,
                      100,
                      function_name="approve",
                      token_address=STRK_ADDRESS)
    ], session_account.address)
    tx = await execute_session_call(oe_call)
    await devnet_client.wait_for_tx(tx.transaction_hash)

    with pytest.raises((TransactionRevertedError, ClientError),
                       match=encode_string_as_hex("BAD_CALLDATA")):
        oe_call = oe.prepare_call([
            get_test_call(destination_account.address,
                          100,
                          function_name="approve",
                          token_address=STRK_ADDRESS),
            get_test_call(session_account.address,
                          100,
                          function_name="approve",
                          token_address=STRK_ADDRESS)
        ], session_account.address)
        tx = await execute_session_call(oe_call)
        await devnet_client.wait_for_tx(tx.transaction_hash)


@pytest.mark.asyncio
@pytest.mark.parametrize("added_signer_type",
                         [SECP256R1_SIGNER_TYPE, WEBAUTHN_SIGNER_TYPE])
@pytest.mark.parametrize(["is_gas_sponsored_execution", "is_v3"],
                         [(False, True), (True, False), (True, True)])
@pytest.mark.parametrize("is_v2_typed_data", [False, True])
async def test_session_cache_invalidation_when_signer_added(
        init_starknet, account_deployer, setup_session_account_env,
        get_spending_limit_amount_spent, get_session_gas_spent,
        added_signer_type, is_gas_sponsored_execution, is_v3,
        is_v2_typed_data):

    _, devnet_client, devnet_account = init_starknet

    session_account, execute_session_call, session_request_builder, _, session_owner_identifier, destination_account = await setup_session_account_env(
        is_gas_sponsored_execution, SECP256R1_SIGNER_TYPE, 0)

    block = await devnet_client.get_block()
    block_timestamp = block.timestamp

    oe = session_request_builder(session_account,
                                 session_owner_identifier,
                                 block_timestamp + 3600,
                                 block_timestamp - 3600,
                                 is_v2_typed_data=is_v2_typed_data)
    # caching session validation
    tx = await execute_session_call(
        oe.prepare_call(
            [get_test_call(destination_account.address, 100)],
            session_account.address,
        ))
    await devnet_client.wait_for_tx(tx.transaction_hash)

    # making sure that session context is cached after first transaction
    # and no need for more validation
    prev_sig = oe.sig
    oe.sig = []
    balance_before = await destination_account.get_balance(FEE_CONTRACT_ADDRESS
                                                           )
    oe_call = oe.prepare_call([
        get_test_call(destination_account.address, 100),
        get_test_call(destination_account.address, 100)
    ], session_account.address)

    tx = await execute_session_call(oe_call, is_v3=is_v3)
    receipt = await devnet_client.wait_for_tx(tx.transaction_hash)
    balance_after = await destination_account.get_balance(FEE_CONTRACT_ADDRESS)
    assert balance_after - balance_before == 200, "Wrong balance change"

    secp256r1_keypair = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    calls = Call(to_addr=session_account.address,
                 selector=get_selector_from_name('add_secp256r1_signer'),
                 calldata=[*secp256r1_pubk, added_signer_type, 0])

    exec_txn = await session_account.execute_v1(
        calls=calls,
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    # making sure that no sig does not work
    oe_call = oe.prepare_call([
        get_test_call(destination_account.address, 100),
        get_test_call(destination_account.address, 100)
    ], session_account.address)
    with pytest.raises((TransactionRevertedError, ClientError),
                       match=encode_string_as_hex("INVALID_SIG")):
        tx = await execute_session_call(oe_call, is_v3=is_v3)
        receipt = await devnet_client.wait_for_tx(tx.transaction_hash)

    # old sig should work because we just added a signer
    oe.sig = prev_sig
    balance_before = await destination_account.get_balance(FEE_CONTRACT_ADDRESS
                                                           )
    oe_call = oe.prepare_call([
        get_test_call(destination_account.address, 100),
        get_test_call(destination_account.address, 100)
    ], session_account.address)

    tx = await execute_session_call(oe_call, is_v3=is_v3)
    receipt = await devnet_client.wait_for_tx(tx.transaction_hash)
    balance_after = await destination_account.get_balance(FEE_CONTRACT_ADDRESS)
    assert balance_after - balance_before == 200, "Wrong balance change"

    token_spent = await get_spending_limit_amount_spent(
        session_account, oe.get_hash(session_account.address),
        FEE_CONTRACT_ADDRESS)
    assert token_spent == 500, 'Wrong token spending'

    if not is_gas_sponsored_execution:
        gas_spent = await get_session_gas_spent(
            session_account, oe.get_hash(session_account.address))
        assert gas_spent == 3 * 10**17 + 3 * 10**6, 'Wrong gas spending'


@pytest.mark.asyncio
@pytest.mark.parametrize("existing_signer_type",
                         [SECP256R1_SIGNER_TYPE, WEBAUTHN_SIGNER_TYPE])
@pytest.mark.parametrize(["is_gas_sponsored_execution", "is_v3"],
                         [(False, True), (True, False), (True, True)])
@pytest.mark.parametrize("is_v2_typed_data", [False, True])
async def test_session_cache_invalidation_when_signer_removed(
        init_starknet, account_deployer, setup_session_account_env,
        get_spending_limit_amount_spent, get_session_gas_spent,
        existing_signer_type, is_gas_sponsored_execution, is_v3,
        is_v2_typed_data):

    _, devnet_client, devnet_account = init_starknet

    session_account, execute_session_call, session_request_builder, _, session_owner_identifier, destination_account = await setup_session_account_env(
        is_gas_sponsored_execution, existing_signer_type, 2)

    block = await devnet_client.get_block()
    block_timestamp = block.timestamp

    oe = session_request_builder(session_account,
                                 session_owner_identifier,
                                 block_timestamp + 3600,
                                 block_timestamp - 3600,
                                 is_v2_typed_data=is_v2_typed_data)
    # caching session validation
    tx = await execute_session_call(
        oe.prepare_call(
            [get_test_call(destination_account.address, 100)],
            session_account.address,
        ))
    await devnet_client.wait_for_tx(tx.transaction_hash)

    # making sure that session context is cached after first transaction
    # and no need for more validation
    prev_sig = oe.sig
    oe.sig = []
    balance_before = await destination_account.get_balance(FEE_CONTRACT_ADDRESS
                                                           )
    oe_call = oe.prepare_call([
        get_test_call(destination_account.address, 100),
        get_test_call(destination_account.address, 100)
    ], session_account.address)

    tx = await execute_session_call(oe_call, is_v3=is_v3)
    receipt = await devnet_client.wait_for_tx(tx.transaction_hash)
    balance_after = await destination_account.get_balance(FEE_CONTRACT_ADDRESS)
    assert balance_after - balance_before == 200, "Wrong balance change"

    calls = Call(to_addr=session_account.address,
                 selector=get_selector_from_name('remove_secp256r1_signer'),
                 calldata=[
                     poseidon_hash_many(
                         flatten_seq(session_account.secp256r1_keypair[1])),
                     existing_signer_type, 0
                 ])

    exec_txn = await session_account.execute_v1(
        calls=calls,
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    # making sure that no sig does not work
    oe_call = oe.prepare_call([
        get_test_call(destination_account.address, 100),
        get_test_call(destination_account.address, 100)
    ], session_account.address)
    with pytest.raises((TransactionRevertedError, ClientError),
                       match=encode_string_as_hex("INVALID_SIG")):
        tx = await execute_session_call(oe_call, is_v3=is_v3)
        receipt = await devnet_client.wait_for_tx(tx.transaction_hash)

    # making sure that old sig does not work as well
    oe.sig = prev_sig
    oe_call = oe.prepare_call([
        get_test_call(destination_account.address, 100),
        get_test_call(destination_account.address, 100)
    ], session_account.address)
    with pytest.raises((TransactionRevertedError, ClientError),
                       match=encode_string_as_hex("INVALID_SIG")):
        tx = await execute_session_call(oe_call, is_v3=is_v3)
        receipt = await devnet_client.wait_for_tx(tx.transaction_hash)

    token_spent = await get_spending_limit_amount_spent(
        session_account, oe.get_hash(session_account.address),
        FEE_CONTRACT_ADDRESS)
    assert token_spent == 300, 'Wrong token spending'

    if not is_gas_sponsored_execution:
        gas_spent = await get_session_gas_spent(
            session_account, oe.get_hash(session_account.address))
        assert gas_spent == 2 * 10**17 + 2 * 10**6, 'Wrong gas spending'


@pytest.mark.asyncio
@pytest.mark.parametrize("multisig_initial_value", [0, 2])
@pytest.mark.parametrize(["is_gas_sponsored_execution", "is_v3"],
                         [(False, True), (True, False), (True, True)])
@pytest.mark.parametrize("is_v2_typed_data", [False, True])
async def test_session_cache_invalidation_when_multisig_changes(
        init_starknet, account_deployer, setup_session_account_env,
        get_spending_limit_amount_spent, get_session_gas_spent,
        multisig_initial_value, is_gas_sponsored_execution, is_v3,
        is_v2_typed_data):

    _, devnet_client, devnet_account = init_starknet

    session_account, execute_session_call, session_request_builder, _, session_owner_identifier, destination_account = await setup_session_account_env(
        is_gas_sponsored_execution, SECP256R1_SIGNER_TYPE,
        multisig_initial_value)

    block = await devnet_client.get_block()
    block_timestamp = block.timestamp

    oe = session_request_builder(session_account,
                                 session_owner_identifier,
                                 block_timestamp + 3600,
                                 block_timestamp - 3600,
                                 is_v2_typed_data=is_v2_typed_data)
    # caching session validation
    tx = await execute_session_call(
        oe.prepare_call(
            [get_test_call(destination_account.address, 100)],
            session_account.address,
        ))
    await devnet_client.wait_for_tx(tx.transaction_hash)

    # making sure that session context is cached after first transaction
    # and no need for more validation
    prev_sig = oe.sig
    oe.sig = []
    balance_before = await destination_account.get_balance(FEE_CONTRACT_ADDRESS
                                                           )
    oe_call = oe.prepare_call([
        get_test_call(destination_account.address, 100),
        get_test_call(destination_account.address, 100)
    ], session_account.address)

    tx = await execute_session_call(oe_call, is_v3=is_v3)
    receipt = await devnet_client.wait_for_tx(tx.transaction_hash)
    balance_after = await destination_account.get_balance(FEE_CONTRACT_ADDRESS)
    assert balance_after - balance_before == 200, "Wrong balance change"

    calls = Call(to_addr=session_account.address,
                 selector=get_selector_from_name('set_multisig_threshold'),
                 calldata=[2 - multisig_initial_value])

    exec_txn = await session_account.execute_v1(
        calls=calls,
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    # making sure that no sig does not work
    oe_call = oe.prepare_call([
        get_test_call(destination_account.address, 100),
        get_test_call(destination_account.address, 100)
    ], session_account.address)
    with pytest.raises((TransactionRevertedError, ClientError),
                       match=encode_string_as_hex("INVALID_SIG")):
        tx = await execute_session_call(oe_call, is_v3=is_v3)
        receipt = await devnet_client.wait_for_tx(tx.transaction_hash)

    # making sure that old sig does not work as well
    oe.sig = prev_sig
    oe_call = oe.prepare_call([
        get_test_call(destination_account.address, 100),
        get_test_call(destination_account.address, 100)
    ], session_account.address)
    with pytest.raises((TransactionRevertedError, ClientError),
                       match=encode_string_as_hex("INVALID_SIG")):
        tx = await execute_session_call(oe_call, is_v3=is_v3)
        receipt = await devnet_client.wait_for_tx(tx.transaction_hash)

    token_spent = await get_spending_limit_amount_spent(
        session_account, oe.get_hash(session_account.address),
        FEE_CONTRACT_ADDRESS)
    assert token_spent == 300, 'Wrong token spending'

    if not is_gas_sponsored_execution:
        gas_spent = await get_session_gas_spent(
            session_account, oe.get_hash(session_account.address))
        assert gas_spent == 2 * 10**17 + 2 * 10**6, 'Wrong gas spending'


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "second_signer_type",
        "multisig_threshold",
        "withdrawal_limit_low",
        "withdrawal_limit_high",
    ],
    [
        (SECP256R1_SIGNER_TYPE, 0, 0, 0),
        (SECP256R1_SIGNER_TYPE, 0, 50 * USDC, 0),
        (SECP256R1_SIGNER_TYPE, 2, 0, 0),
        (SECP256R1_SIGNER_TYPE, 2, 50 * USDC, 0),
        (SECP256R1_SIGNER_TYPE, 2, 50 * USDC, 100 * USDC),
        (WEBAUTHN_SIGNER_TYPE, 0, 0, 0),
        (WEBAUTHN_SIGNER_TYPE, 0, 50 * USDC, 0),
        (WEBAUTHN_SIGNER_TYPE, 2, 0, 0),
        (WEBAUTHN_SIGNER_TYPE, 2, 50 * USDC, 0),
        (WEBAUTHN_SIGNER_TYPE, 2, 50 * USDC, 100 * USDC),
    ],
    ids=[
        "with_secp256r1_no_multisig",
        "with_secp256r1_no_multisig_dwl_low",
        "with_secp256r1_multisig",
        "with_secp256r1_multisig_dwl_low",
        "with_secp256r1_multisig_dwl_low_high",
        "with_webauthn_no_multisig",
        "with_webauthn_no_multisig_dwl_low",
        "with_webauthn_multisig",
        "with_webauthn_multisig_dwl_low",
        "with_webauthn_multisig_dwl_low_high",
    ],
)
@pytest.mark.parametrize("is_v2_typed_data", [False, True])
async def test_session_execution_with_etd_present(
        init_starknet, account_deployer, setup_session_account_env,
        second_signer_type, withdrawal_limit_low, withdrawal_limit_high,
        multisig_threshold, is_v2_typed_data):
    is_v3 = True
    devnet_url, devnet_client, devnet_account = init_starknet
    stark_privk = random.randint(1, 10**10)
    session_account, execute_session_call, session_request_builder, event_name, session_owner_identifier, destination_account = await setup_session_account_env(
        False,
        second_signer_type,
        multisig_threshold,
        withdrawal_limit_low=withdrawal_limit_low,
        withdrawal_limit_high=withdrawal_limit_high,
        stark_privk_input=stark_privk)

    block = await devnet_client.get_block()
    block_timestamp = block.timestamp

    oe = session_request_builder(session_account,
                                 session_owner_identifier,
                                 block_timestamp + 360000000,
                                 block_timestamp - 3600,
                                 is_v2_typed_data=is_v2_typed_data)

    balance_before = await destination_account.get_balance(FEE_CONTRACT_ADDRESS
                                                           )
    oe_call = oe.prepare_call([
        get_test_call(destination_account.address, 100),
        get_test_call(destination_account.address, 100)
    ], session_account.address)

    tx = await execute_session_call(oe_call, is_v3=is_v3)
    receipt = await devnet_client.wait_for_tx(tx.transaction_hash)
    balance_after = await destination_account.get_balance(FEE_CONTRACT_ADDRESS)
    assert balance_after - balance_before == 200, "Wrong balance change"

    deferred_remove_call = Call(
        to_addr=session_account.address,
        selector=get_selector_from_name("deferred_remove_signers"),
        calldata=[],
    )
    await execute_with_signer(session_account,
                              deferred_remove_call,
                              create_stark_signer(stark_privk),
                              max_fee=10**16)

    deferred_req = await devnet_client.call_contract(
        Call(
            to_addr=session_account.address,
            selector=get_selector_from_name("get_deferred_remove_signers"),
            calldata=[],
        ))
    account_etd = 24 * 4 * 60 * 60
    expected_timestamp = block_timestamp + account_etd

    assert expected_timestamp - 30 <= deferred_req[0] <= expected_timestamp + 30

    requests.post(f"{devnet_url}/increase_time",
                  json={"time": int(24 * 5 * 60 * 60)})

    balance_before = await destination_account.get_balance(FEE_CONTRACT_ADDRESS
                                                           )
    oe_call = oe.prepare_call([
        get_test_call(destination_account.address, 100),
        get_test_call(destination_account.address, 100)
    ], session_account.address)

    with pytest.raises((TransactionRevertedError, ClientError),
                       match=encode_string_as_hex("INVALID_SIGNER")):
        tx = await execute_session_call(oe_call, is_v3=is_v3)
        receipt = await devnet_client.wait_for_tx(tx.transaction_hash)


@pytest.mark.asyncio
@pytest.mark.parametrize("is_revoked_on_start", [False, True])
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
@pytest.mark.parametrize(["is_gas_sponsored_execution", "is_v3"],
                         [(False, True), (True, False), (True, True)])
@pytest.mark.parametrize("is_v2_typed_data", [False, True])
async def test_session_execution_revoke(init_starknet, account_deployer,
                                        setup_session_account_env,
                                        is_revoked_on_start,
                                        second_signer_type, multisig_threshold,
                                        is_gas_sponsored_execution, is_v3,
                                        is_v2_typed_data):
    _, devnet_client, devnet_account = init_starknet
    session_account, execute_session_call, session_request_builder, event_name, session_owner_identifier, destination_account = await setup_session_account_env(
        is_gas_sponsored_execution, second_signer_type, multisig_threshold)

    block = await devnet_client.get_block()
    block_timestamp = block.timestamp

    oe = session_request_builder(session_account,
                                 session_owner_identifier,
                                 block_timestamp + 3600,
                                 block_timestamp - 3600,
                                 is_v2_typed_data=is_v2_typed_data)

    balance_before = await destination_account.get_balance(FEE_CONTRACT_ADDRESS
                                                           )

    oe_call = oe.prepare_call([
        get_test_call(destination_account.address, 100),
        get_test_call(destination_account.address, 100)
    ], session_account.address)

    if not is_revoked_on_start:
        tx = await execute_session_call(oe_call, is_v3=is_v3)
        receipt = await devnet_client.wait_for_tx(tx.transaction_hash)
        balance_after = await destination_account.get_balance(
            FEE_CONTRACT_ADDRESS)
        assert balance_after - balance_before == 200, "Wrong balance change"

    revoke_tx = await session_account.execute_v1(Call(
        to_addr=session_account.address,
        selector=get_selector_from_name("revoke_session"),
        calldata=[oe.get_hash(session_account.address)]),
                                                 max_fee=10**17)

    receipt = await devnet_client.wait_for_tx(revoke_tx.transaction_hash)
    assert txn_receipt_contains_event(
        receipt,
        [
            get_selector_from_name("SessionRevoked"),
            oe.get_hash(session_account.address)
        ],
        [],
        match_data=True,
    ) is True, "no execute session revoked event"

    with pytest.raises((TransactionRevertedError, ClientError),
                       match=encode_string_as_hex("SESSION_REVOKED")):
        tx = await execute_session_call(oe_call, is_v3=is_v3)
        await devnet_client.wait_for_tx(tx.transaction_hash)


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
@pytest.mark.parametrize("is_gas_sponsored_execution_first", [False, True])
@pytest.mark.parametrize("is_gas_sponsored_execution_second", [True, False])
@pytest.mark.parametrize("is_v2_typed_data", [False, True])
async def test_session_multiple_concurrent(
        init_starknet, account_deployer, setup_session_account_env,
        second_signer_type, multisig_threshold,
        is_gas_sponsored_execution_first, is_gas_sponsored_execution_second,
        is_v2_typed_data):
    _, devnet_client, devnet_account = init_starknet

    session_account, execute_session_call, session_request_builder, event_name, session_owner_identifier, destination_account = await setup_session_account_env(
        is_gas_sponsored_execution_first, second_signer_type,
        multisig_threshold)

    block = await devnet_client.get_block()
    block_timestamp = block.timestamp

    oe1 = session_request_builder(session_account,
                                  session_owner_identifier,
                                  block_timestamp + 3600,
                                  block_timestamp - 3600,
                                  is_v2_typed_data=is_v2_typed_data)
    _, second_execute_session_call, second_session_request_builder, second_event_name, second_session_owner_identifier, _ = await setup_session_account_env(
        is_gas_sponsored_execution_second,
        second_signer_type,
        multisig_threshold,
        existing_account=session_account)

    oe2 = second_session_request_builder(
        session_account,
        second_session_owner_identifier,
        block_timestamp + 1600,
        block_timestamp - 3600,
        calls=[
            Call(
                to_addr=int(FEE_CONTRACT_ADDRESS, 16),
                selector=get_selector_from_name("transfer"),
                calldata=[],
            ),
            Call(
                to_addr=STRK_ADDRESS,
                selector=get_selector_from_name("test1"),
                calldata=[],
            ),
            Call(
                to_addr=int(FEE_CONTRACT_ADDRESS, 16),
                selector=get_selector_from_name("test2"),
                calldata=[],
            ),
        ])

    balance_before = await destination_account.get_balance(FEE_CONTRACT_ADDRESS
                                                           )

    oe_call = oe1.prepare_call([
        get_test_call(destination_account.address, 100),
        get_test_call(destination_account.address, 100)
    ], session_account.address)

    tx = await execute_session_call(oe_call)
    receipt = await devnet_client.wait_for_tx(tx.transaction_hash)
    balance_after = await destination_account.get_balance(FEE_CONTRACT_ADDRESS)
    assert balance_after - balance_before == 200, "Wrong balance change"

    assert txn_receipt_contains_event(
        receipt,
        [
            get_selector_from_name(event_name),
            oe1.get_hash(session_account.address)
        ],
        [
            session_owner_identifier, oe1.execute_after, oe1.execute_before,
            receipt.transaction_hash
        ],
        match_data=True,
    ) is True, "no execute session started event"

    balance_before = balance_after

    oe_call2 = oe2.prepare_call([
        get_test_call(destination_account.address, 50),
        get_test_call(destination_account.address, 50)
    ], session_account.address)

    tx = await second_execute_session_call(oe_call2)
    receipt = await devnet_client.wait_for_tx(tx.transaction_hash)
    balance_after = await destination_account.get_balance(FEE_CONTRACT_ADDRESS)
    assert balance_after - balance_before == 100, "Wrong balance change"

    assert txn_receipt_contains_event(
        receipt,
        [
            get_selector_from_name(second_event_name),
            oe2.get_hash(session_account.address)
        ],
        [
            second_session_owner_identifier, oe2.execute_after,
            oe2.execute_before, receipt.transaction_hash
        ],
        match_data=True,
    ) is True, "no execute session started event"


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
@pytest.mark.parametrize("is_after_cache", [True, False])
@pytest.mark.parametrize("is_gas_sponsored_execution", [False, True])
@pytest.mark.parametrize("is_v2_typed_data", [False, True])
async def test_session_execution_expiry(init_starknet, account_deployer,
                                        setup_session_account_env,
                                        second_signer_type, multisig_threshold,
                                        is_after_cache,
                                        is_gas_sponsored_execution,
                                        is_v2_typed_data):
    devnet_url, devnet_client, devnet_account = init_starknet

    session_account, execute_session_call, session_request_builder, _, session_owner_identifier, destination_account = await setup_session_account_env(
        is_gas_sponsored_execution, second_signer_type, multisig_threshold)

    block = await devnet_client.get_block()
    block_timestamp = block.timestamp

    oe = session_request_builder(session_account,
                                 session_owner_identifier,
                                 block_timestamp + 13600,
                                 block_timestamp + 600,
                                 is_v2_typed_data=is_v2_typed_data)

    with pytest.raises((TransactionRevertedError, ClientError),
                       match=encode_string_as_hex("INVALID_TIMESTAMP")):
        tx = await execute_session_call(
            oe.prepare_call([get_test_call(destination_account.address, 100)],
                            session_account.address), )
        await devnet_client.wait_for_tx(tx.transaction_hash)

    if is_after_cache:
        requests.post(f"{devnet_url}/increase_time", json={"time": int(10000)})
        balance_before = await destination_account.get_balance(
            FEE_CONTRACT_ADDRESS)
        block = await devnet_client.get_block()
        block_timestamp = block.timestamp
        tx = await execute_session_call(
            oe.prepare_call([get_test_call(destination_account.address, 100)],
                            session_account.address))
        await devnet_client.wait_for_tx(tx.transaction_hash)
        balance_after = await destination_account.get_balance(
            FEE_CONTRACT_ADDRESS)
        assert balance_after - balance_before == 100, "Wrong balance change"

    requests.post(f"{devnet_url}/increase_time",
                  json={"time": int(2 * 24 * 60 * 60)})

    with pytest.raises((TransactionRevertedError, ClientError),
                       match=encode_string_as_hex("INVALID_TIMESTAMP")):
        tx = await execute_session_call(
            oe.prepare_call([get_test_call(destination_account.address, 100)],
                            session_account.address), )
        await devnet_client.wait_for_tx(tx.transaction_hash)


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
@pytest.mark.parametrize("is_after_cache", [False, True])
@pytest.mark.parametrize("is_gas_sponsored_execution", [True, False])
@pytest.mark.parametrize("is_v2_typed_data", [False, True])
async def test_session_execution_with_invalid_call(
        init_starknet, account_deployer, setup_session_account_env,
        second_signer_type, multisig_threshold, is_after_cache,
        is_gas_sponsored_execution, is_v2_typed_data):
    _, devnet_client, devnet_account = init_starknet

    session_account, execute_session_call, session_request_builder, _, session_owner_identifier, destination_account = await setup_session_account_env(
        is_gas_sponsored_execution, second_signer_type, multisig_threshold)

    block = await devnet_client.get_block()
    block_timestamp = block.timestamp

    oe = session_request_builder(session_account,
                                 session_owner_identifier,
                                 block_timestamp + 3600,
                                 block_timestamp - 3600,
                                 is_v2_typed_data=is_v2_typed_data)

    if is_after_cache:
        balance_before = await destination_account.get_balance(
            FEE_CONTRACT_ADDRESS)
        tx = await execute_session_call(
            oe.prepare_call(
                [get_test_call(destination_account.address, 100)],
                session_account.address,
            ))
        await devnet_client.wait_for_tx(tx.transaction_hash)
        balance_after = await destination_account.get_balance(
            FEE_CONTRACT_ADDRESS)
        assert balance_after - balance_before == 100, "Wrong balance change"

    with pytest.raises((TransactionRevertedError, ClientError),
                       match=encode_string_as_hex("BAD_CALL")):
        oe_call = oe.prepare_call([
            get_test_call(destination_account.address, 100),
            get_test_call(destination_account.address, 100)
        ], session_account.address)

        # overriding the call with an endpoint that's not part of the session context
        if is_gas_sponsored_execution:
            if is_v2_typed_data:
                oe_call.calldata[31] = get_selector_from_name(
                    'increase_allowance')
            else:
                oe_call.calldata[18] = get_selector_from_name(
                    'increase_allowance')
        else:
            oe_call[1].selector = get_selector_from_name('increase_allowance')

        tx = await execute_session_call(oe_call)
        await devnet_client.wait_for_tx(tx.transaction_hash)


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
@pytest.mark.parametrize("is_gas_sponsored_execution", [False, True])
@pytest.mark.parametrize("is_v2_typed_data", [False, True])
async def test_session_execution_invalid_sig(init_starknet, account_deployer,
                                             setup_session_account_env,
                                             second_signer_type,
                                             multisig_threshold,
                                             is_gas_sponsored_execution,
                                             is_v2_typed_data):
    _, devnet_client, devnet_account = init_starknet

    session_account, execute_session_call, session_request_builder, _, session_owner_identifier, destination_account = await setup_session_account_env(
        is_gas_sponsored_execution, second_signer_type, multisig_threshold)

    block = await devnet_client.get_block()
    block_timestamp = block.timestamp

    oe = session_request_builder(session_account,
                                 session_owner_identifier,
                                 block_timestamp + 3600,
                                 block_timestamp - 3600,
                                 is_v2_typed_data=is_v2_typed_data)

    oe.sig = []
    oe_call = oe.prepare_call([
        get_test_call(destination_account.address, 100),
        get_test_call(destination_account.address, 100)
    ], session_account.address)

    # trying with an empty sig
    with pytest.raises((TransactionRevertedError, ClientError),
                       match=encode_string_as_hex("INVALID_SIG")):
        tx = await execute_session_call(oe_call)
        await devnet_client.wait_for_tx(tx.transaction_hash)

    # trying with a faulty sig
    oe = session_request_builder(session_account,
                                 session_owner_identifier,
                                 block_timestamp + 3600,
                                 block_timestamp - 3600,
                                 is_v2_typed_data=is_v2_typed_data)
    oe.sig[1] += 1

    oe_call = oe.prepare_call([
        get_test_call(destination_account.address, 100),
        get_test_call(destination_account.address, 100)
    ], session_account.address)

    with pytest.raises((TransactionRevertedError, ClientError),
                       match=encode_string_as_hex("INVALID_SIG")):
        tx = await execute_session_call(oe_call)
        await devnet_client.wait_for_tx(tx.transaction_hash)


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
@pytest.mark.parametrize("is_gas_sponsored_execution", [False, True])
@pytest.mark.parametrize("is_v2_typed_data", [False, True])
async def test_session_execution_invalid_caller(
        init_starknet, account_deployer, setup_session_account_env,
        second_signer_type, multisig_threshold, is_gas_sponsored_execution,
        is_v2_typed_data):
    _, devnet_client, devnet_account = init_starknet

    session_account, execute_session_call, session_request_builder, _, session_owner_identifier, destination_account = await setup_session_account_env(
        is_gas_sponsored_execution, second_signer_type, multisig_threshold)

    session_owner_identifier += 1
    block = await devnet_client.get_block()
    block_timestamp = block.timestamp

    oe = session_request_builder(session_account,
                                 session_owner_identifier,
                                 block_timestamp + 3600,
                                 block_timestamp - 3600,
                                 is_v2_typed_data=is_v2_typed_data)

    oe_call = oe.prepare_call([
        get_test_call(destination_account.address, 100),
        get_test_call(destination_account.address, 100)
    ], session_account.address)

    with pytest.raises((TransactionRevertedError, ClientError), ):
        tx = await execute_session_call(oe_call)
        await devnet_client.wait_for_tx(tx.transaction_hash)


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
@pytest.mark.parametrize("is_v2_typed_data", [False, True])
async def test_session_gas_limit_overload(
    init_starknet,
    account_deployer,
    setup_session_account_env,
    get_session_gas_spent,
    second_signer_type,
    multisig_threshold,
    is_v2_typed_data,
):
    devnet_url, devnet_client, devnet_account = init_starknet

    session_account, execute_session_call, session_request_builder, _, session_owner_identifier, destination_account = await setup_session_account_env(
        False, second_signer_type, multisig_threshold)

    block = await devnet_client.get_block()
    block_timestamp = block.timestamp

    strk_gas_limit = 10 * 10**18

    oe = session_request_builder(session_account,
                                 session_owner_identifier,
                                 block_timestamp + 3600,
                                 block_timestamp - 3600,
                                 strk_gas_limit=strk_gas_limit,
                                 is_v2_typed_data=is_v2_typed_data)

    with pytest.raises(ClientError, match=encode_string_as_hex("INVALID_FEE")):
        tx = await execute_session_call(
            oe.prepare_call([get_test_call(destination_account.address, 100)],
                            session_account.address),
            max_fee=(10 * 10**18 + 1),
            is_v3=True)
        await devnet_client.wait_for_tx(tx.transaction_hash)

    gas_spent = await get_session_gas_spent(
        session_account, oe.get_hash(session_account.address))
    assert gas_spent == 0, "No gas spending at this point"

    balance_before = await destination_account.get_balance(FEE_CONTRACT_ADDRESS
                                                           )
    tx = await execute_session_call(oe.prepare_call(
        [get_test_call(destination_account.address, 100)],
        session_account.address,
    ),
                                    max_fee=60 * 10**17,
                                    is_v3=True)
    await devnet_client.wait_for_tx(tx.transaction_hash)
    balance_after = await destination_account.get_balance(FEE_CONTRACT_ADDRESS)
    assert balance_after - balance_before == 100, "Wrong balance change"
    balance_before = await destination_account.get_balance(FEE_CONTRACT_ADDRESS
                                                           )
    gas_spent = await get_session_gas_spent(
        session_account, oe.get_hash(session_account.address))
    # v3 txs have a bit extra taken in max fee, see "execute_with_signer"
    assert gas_spent == 60 * 10**17 + 60 * 10**6, "wrong strk gas spending"

    tx = await execute_session_call(oe.prepare_call(
        [get_test_call(destination_account.address, 100)],
        session_account.address,
    ),
                                    max_fee=39.9 * 10**17,
                                    is_v3=True)
    await devnet_client.wait_for_tx(tx.transaction_hash)
    balance_after = await destination_account.get_balance(FEE_CONTRACT_ADDRESS)
    assert balance_after - balance_before == 100, "Wrong balance change"

    gas_spent = await get_session_gas_spent(
        session_account, oe.get_hash(session_account.address))
    # v3 txs have a bit extra taken in max fee, see "execute_with_signer"
    assert gas_spent == 60 * 10**17 + 60 * 10**6 + int(39.9 * 10**17) + int(
        39.9 * 10**6), "wrong strk gas spending"

    with pytest.raises(ClientError, match=encode_string_as_hex("INVALID_FEE")):
        tx = await execute_session_call(
            oe.prepare_call([get_test_call(destination_account.address, 100)],
                            session_account.address),
            max_fee=10 * 10**17,
            is_v3=True)
        await devnet_client.wait_for_tx(tx.transaction_hash)


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
@pytest.mark.parametrize("is_gas_sponsored_execution", [False, True])
@pytest.mark.parametrize("is_after_cache", [False, True])
@pytest.mark.parametrize("is_fail_on_high_u256", [False, True])
@pytest.mark.parametrize("dai_address", [DAIV0_ADDRESS, DAIV2_ADDRESS])
@pytest.mark.parametrize("dai_transfer_from_entrypoint",
                         ["transfer_from", "transferFrom"])
@pytest.mark.parametrize("is_v2_typed_data", [False, True])
async def test_session_spending_limits(
        init_starknet, account_deployer, usdc_token, setup_session_account_env,
        get_spending_limit_amount_spent, second_signer_type,
        multisig_threshold, is_gas_sponsored_execution, is_after_cache,
        is_fail_on_high_u256, dai_address, dai_transfer_from_entrypoint,
        is_v2_typed_data):
    devnet_url, devnet_client, devnet_account = init_starknet

    session_account, execute_session_call, session_request_builder, _, session_owner_identifier, destination_account = await setup_session_account_env(
        is_gas_sponsored_execution, second_signer_type, multisig_threshold)

    transfer_tx = await devnet_account.execute_v1(
        Call(
            to_addr=usdc_token.address,
            selector=get_selector_from_name("transfer"),
            calldata=[
                session_account.address,
                *(to_uint256(ETHER * 10)),
            ],
        ),
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(transfer_tx.transaction_hash)

    block = await devnet_client.get_block()
    block_timestamp = block.timestamp

    relevant_erc20_entrypoints = [
        "approve",
        "transfer",
    ]
    relevant_snake_erc20_entrypoints = []

    calls = [
        *[
            AllowedMethod(to_addr=STRK_ADDRESS,
                          selector=get_selector_from_name(name),
                          calldata_validations=[])
            for name in relevant_erc20_entrypoints +
            relevant_snake_erc20_entrypoints
        ],
        *[
            AllowedMethod(to_addr=usdc_token.address,
                          selector=get_selector_from_name(name),
                          calldata_validations=[])
            for name in relevant_erc20_entrypoints
        ],
        AllowedMethod(to_addr=int(FEE_CONTRACT_ADDRESS, 16),
                      selector=get_selector_from_name("transfer"),
                      calldata_validations=[]),
        AllowedMethod(
            to_addr=dai_address,
            selector=get_selector_from_name(dai_transfer_from_entrypoint),
            calldata_validations=[]),
    ]

    spending_limits = [[STRK_ADDRESS, 5 * 10**18],
                       [usdc_token.address, 5 * 10**18],
                       [dai_address, 5 * 10**18]]

    oe = session_request_builder(session_account,
                                 session_owner_identifier,
                                 block_timestamp + 3600,
                                 block_timestamp - 3600,
                                 calls=calls,
                                 spending_limits=spending_limits,
                                 is_v2_typed_data=is_v2_typed_data)

    if is_after_cache:
        # sending a passing tx to test cached state spending limit checks
        balance_before = await destination_account.get_balance(
            FEE_CONTRACT_ADDRESS)
        tx = await execute_session_call(
            oe.prepare_call(
                [get_test_call(destination_account.address, 10**18)],
                session_account.address,
            ))
        await devnet_client.wait_for_tx(tx.transaction_hash)
        balance_after = await destination_account.get_balance(
            FEE_CONTRACT_ADDRESS)

        spending = await get_spending_limit_amount_spent(
            session_account, oe.get_hash(session_account.address),
            STRK_ADDRESS)
        assert spending == 0, "wrong strk spending"

        spending = await get_spending_limit_amount_spent(
            session_account, oe.get_hash(session_account.address),
            usdc_token.address)
        assert spending == 0, "wrong usdc spending"

    # failing on the first session tx
    for entrypoint in relevant_erc20_entrypoints + relevant_snake_erc20_entrypoints:
        with pytest.raises((ClientError, TransactionRevertedError),
                           match=encode_string_as_hex("BAD_SPENDING")):
            tx = await execute_session_call(
                oe.prepare_call([
                    get_test_call(destination_account.address,
                                  10 * 10**18,
                                  token_address=STRK_ADDRESS,
                                  function_name=entrypoint,
                                  is_high_amount=is_fail_on_high_u256)
                ], session_account.address))
            await devnet_client.wait_for_tx(tx.transaction_hash)

    for entrypoint in relevant_erc20_entrypoints:
        with pytest.raises((ClientError, TransactionRevertedError),
                           match=encode_string_as_hex("BAD_SPENDING")):
            tx = await execute_session_call(
                oe.prepare_call([
                    get_test_call(destination_account.address,
                                  10 * 10**18,
                                  token_address=usdc_token.address,
                                  function_name=entrypoint,
                                  is_high_amount=is_fail_on_high_u256)
                ], session_account.address))
            await devnet_client.wait_for_tx(tx.transaction_hash)

    # few working txs

    for entrypoint in relevant_erc20_entrypoints + relevant_snake_erc20_entrypoints:
        tx = await execute_session_call(
            oe.prepare_call([
                get_test_call(destination_account.address,
                              10**18,
                              token_address=STRK_ADDRESS,
                              function_name=entrypoint)
            ], session_account.address))
        await devnet_client.wait_for_tx(tx.transaction_hash)

    for entrypoint in relevant_erc20_entrypoints:
        tx = await execute_session_call(
            oe.prepare_call([
                get_test_call(destination_account.address,
                              10**18,
                              token_address=usdc_token.address,
                              function_name=entrypoint)
            ], session_account.address))
        await devnet_client.wait_for_tx(tx.transaction_hash)

    spending = await get_spending_limit_amount_spent(
        session_account, oe.get_hash(session_account.address), STRK_ADDRESS)
    assert spending == 2 * 10**18, "wrong strk spending"

    spending = await get_spending_limit_amount_spent(
        session_account, oe.get_hash(session_account.address),
        usdc_token.address)
    assert spending == 2 * 10**18, "wrong usdc spending"

    # fail txs
    for entrypoint in relevant_erc20_entrypoints + relevant_snake_erc20_entrypoints:
        with pytest.raises((ClientError, TransactionRevertedError),
                           match=encode_string_as_hex("BAD_SPENDING")):
            tx = await execute_session_call(
                oe.prepare_call([
                    get_test_call(destination_account.address,
                                  3 * 10**18 + 1,
                                  token_address=STRK_ADDRESS,
                                  function_name=entrypoint)
                ], session_account.address))
            await devnet_client.wait_for_tx(tx.transaction_hash)

    for entrypoint in relevant_erc20_entrypoints:
        with pytest.raises((ClientError, TransactionRevertedError),
                           match=encode_string_as_hex("BAD_SPENDING")):
            tx = await execute_session_call(
                oe.prepare_call([
                    get_test_call(destination_account.address,
                                  3 * 10**18 + 1,
                                  token_address=usdc_token.address,
                                  function_name=entrypoint)
                ], session_account.address))
            await devnet_client.wait_for_tx(tx.transaction_hash)

    # make sure non spending limit txs succeed
    balance_before = await destination_account.get_balance(FEE_CONTRACT_ADDRESS
                                                           )
    tx = await execute_session_call(
        oe.prepare_call(
            [get_test_call(destination_account.address, 8 * 10**18)],
            session_account.address,
        ))
    await devnet_client.wait_for_tx(tx.transaction_hash)
    balance_after = await destination_account.get_balance(FEE_CONTRACT_ADDRESS)

    # check dai
    with pytest.raises((ClientError, TransactionRevertedError),
                       match=encode_string_as_hex("BAD_SPENDING")):
        tx = await execute_session_call(
            oe.prepare_call([
                Call(to_addr=dai_address,
                     selector=get_selector_from_name(
                         dai_transfer_from_entrypoint),
                     calldata=[
                         session_account.address, destination_account.address,
                         2 * 10**18, 0
                     ]),
                Call(to_addr=dai_address,
                     selector=get_selector_from_name(
                         dai_transfer_from_entrypoint),
                     calldata=[
                         session_account.address, destination_account.address,
                         2 * 10**18, 0
                     ]),
                Call(to_addr=dai_address,
                     selector=get_selector_from_name(
                         dai_transfer_from_entrypoint),
                     calldata=[
                         session_account.address, destination_account.address,
                         2 * 10**18, 0
                     ]),
            ], session_account.address))
        await devnet_client.wait_for_tx(tx.transaction_hash)

    with pytest.raises((ClientError, TransactionRevertedError),
                       match="is not deployed"):
        tx = await execute_session_call(
            oe.prepare_call([
                Call(to_addr=dai_address,
                     selector=get_selector_from_name(
                         dai_transfer_from_entrypoint),
                     calldata=[
                         session_account.address, destination_account.address,
                         2 * 10**18, 0
                     ]),
                Call(to_addr=dai_address,
                     selector=get_selector_from_name(
                         dai_transfer_from_entrypoint),
                     calldata=[
                         session_account.address, destination_account.address,
                         2 * 10**18, 0
                     ]),
            ], session_account.address))
        await devnet_client.wait_for_tx(tx.transaction_hash)


@pytest.mark.asyncio
@pytest.mark.parametrize("is_after_cache", [False, True])
@pytest.mark.parametrize("is_v2_typed_data", [False, True])
async def test_session_revoke_via_outside_execution(
    init_starknet,
    account_deployer,
    setup_session_account_env,
    is_after_cache,
    is_v2_typed_data,
):
    devnet_url, devnet_client, devnet_account = init_starknet

    session_account, execute_session_call, session_request_builder, _, session_owner_identifier, destination_account = await setup_session_account_env(
        False, None, 0)

    block = await devnet_client.get_block()
    block_timestamp = block.timestamp
    oe = session_request_builder(session_account,
                                 session_owner_identifier,
                                 block_timestamp + 3600,
                                 block_timestamp - 3600,
                                 is_v2_typed_data=is_v2_typed_data)

    if is_after_cache:
        tx = await execute_session_call(
            oe.prepare_call(
                [get_test_call(destination_account.address, 100)],
                session_account.address,
            ))
        await devnet_client.wait_for_tx(tx.transaction_hash)

    out_ex = OutsideExecution(
        account=session_account,
        calls=[
            Call(to_addr=session_account.address,
                 selector=get_selector_from_name("revoke_session"),
                 calldata=[oe.get_hash(session_account.address)])
        ],
        execute_before=block_timestamp + 3600,
        execute_after=block_timestamp - 3600)

    tx = await devnet_account.execute_v1(
        out_ex.prepare_call(session_account.address),
        max_fee=10**17,
    )
    receipt = await devnet_client.wait_for_tx(tx.transaction_hash)

    assert txn_receipt_contains_event(
        receipt,
        [
            get_selector_from_name("SessionRevoked"),
            oe.get_hash(session_account.address)
        ],
        [],
        match_data=True,
    ) is True, "no execute session revoked event"

    res = await devnet_client.call_contract(
        Call(
            to_addr=session_account.address,
            selector=get_selector_from_name("is_session_revoked"),
            calldata=[oe.get_hash(session_account.address)],
        ))
    assert res[0] == 1, "Session isn't revoked"


@pytest.mark.asyncio
@pytest.mark.parametrize("is_gas_sponsored_execution", [False, True])
@pytest.mark.parametrize("is_v2_typed_data", [False, True])
async def test_session_self_calls_are_blocked(
    init_starknet,
    account_deployer,
    setup_session_account_env,
    is_gas_sponsored_execution,
    is_v2_typed_data,
):
    devnet_url, devnet_client, devnet_account = init_starknet

    session_account, execute_session_call, session_request_builder, _, session_owner_identifier, destination_account = await setup_session_account_env(
        is_gas_sponsored_execution, None, 0)

    block = await devnet_client.get_block()
    block_timestamp = block.timestamp
    oe = session_request_builder(
        session_account,
        session_owner_identifier,
        block_timestamp + 3600,
        block_timestamp - 3600,
        calls=[
            AllowedMethod(to_addr=session_account.address,
                          selector=get_selector_from_name("upgrade"),
                          calldata_validations=[])
        ],
        is_v2_typed_data=is_v2_typed_data)

    with pytest.raises((ClientError, TransactionRevertedError),
                       match=encode_string_as_hex("SELF_CALL")):
        tx = await execute_session_call(
            oe.prepare_call([
                Call(to_addr=session_account.address,
                     selector=get_selector_from_name("upgrade"),
                     calldata=[0])
            ], session_account.address))
        await devnet_client.wait_for_tx(tx.transaction_hash)


@pytest.mark.asyncio
@pytest.mark.parametrize("is_gas_sponsored_execution", [False, True])
@pytest.mark.parametrize("is_v2_typed_data", [False, True])
async def test_session_bad_call_hints(
    init_starknet,
    account_deployer,
    setup_session_account_env,
    is_gas_sponsored_execution,
    is_v2_typed_data,
):
    devnet_url, devnet_client, devnet_account = init_starknet

    session_account, execute_session_call, session_request_builder, _, session_owner_identifier, destination_account = await setup_session_account_env(
        is_gas_sponsored_execution, None, 0)

    block = await devnet_client.get_block()
    block_timestamp = block.timestamp
    oe = session_request_builder(session_account,
                                 session_owner_identifier,
                                 block_timestamp + 3600,
                                 block_timestamp - 3600,
                                 is_v2_typed_data=is_v2_typed_data)

    # sending call hints with bad size
    with pytest.raises((ClientError, TransactionRevertedError),
                       match=encode_string_as_hex("BAD_CALL_HINT")):
        tx = await execute_session_call(
            oe.prepare_call([
                Call(to_addr=STRK_ADDRESS,
                     selector=get_selector_from_name("approve"),
                     calldata=[0])
            ],
                            session_account.address,
                            override_call_hints=[0, 1, 2]))
        await devnet_client.wait_for_tx(tx.transaction_hash)

    # sending wrong hint as "approve" is in index 0
    with pytest.raises((ClientError, TransactionRevertedError),
                       match=encode_string_as_hex("BAD_CALL")):
        tx = await execute_session_call(
            oe.prepare_call([
                Call(to_addr=STRK_ADDRESS,
                     selector=get_selector_from_name("approve"),
                     calldata=[0])
            ],
                            session_account.address,
                            override_call_hints=[1]))
        await devnet_client.wait_for_tx(tx.transaction_hash)

    # sending an index much larger than allowed method list
    with pytest.raises((ClientError, TransactionRevertedError),
                       match=encode_string_as_hex("BAD_CALL")):
        tx = await execute_session_call(
            oe.prepare_call([
                Call(to_addr=STRK_ADDRESS,
                     selector=get_selector_from_name("approve"),
                     calldata=[0])
            ],
                            session_account.address,
                            override_call_hints=[10000]))
        await devnet_client.wait_for_tx(tx.transaction_hash)


@pytest.mark.asyncio
@pytest.mark.parametrize("is_v2_typed_data", [True])
async def test_session_owner_signature_length(
    init_starknet,
    account_deployer,
    setup_session_account_env,
    is_v2_typed_data,
):
    devnet_url, devnet_client, devnet_account = init_starknet

    session_account, execute_session_call, session_request_builder, _, session_owner_identifier, destination_account = await setup_session_account_env(
        False, None, 0)

    block = await devnet_client.get_block()
    block_timestamp = block.timestamp
    oe = session_request_builder(session_account,
                                 session_owner_identifier,
                                 block_timestamp + 3600,
                                 block_timestamp - 3600,
                                 is_v2_typed_data=is_v2_typed_data)

    oe_call = oe.prepare_call([
        get_test_call(destination_account.address, 100),
        get_test_call(destination_account.address,
                      100,
                      function_name="approve",
                      token_address=STRK_ADDRESS)
    ], session_account.address)
    with pytest.raises((ClientError, TransactionRevertedError),
                       match=encode_string_as_hex("INVALID_SIG")):
        tx = await execute_session_call(
            oe_call,
            is_v3=True,
            signer=create_legacy_stark_signer_oversized_length(
                devnet_account.signer.private_key))
        await devnet_client.wait_for_tx(tx.transaction_hash)
