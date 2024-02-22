import e2e.utils.utils_v2 as utils_v2
from e2e.utils.utils_v2 import MAX_EXECUTE_FEE_ETH, MAX_SIGN_FEE_ETH, MAX_EXECUTE_FEE_STRK, MAX_SIGN_FEE_STRK, TestSigner, check_pending_tx_event, STRK_ADDRESS, EXECUTION_RESOURCE_BOUNDS, SIGNER_RESOURCE_BOUNDS, HIGH_EXECUTION_RESOURCE_BOUNDS, HIGH_SIGNER_RESOURCE_BOUNDS
from e2e.utils.fixtures_moa import *

import pytest

from starknet_py.constants import FEE_CONTRACT_ADDRESS
from starknet_py.net.client_errors import ClientError
from starknet_py.net.full_node_client import FullNodeClient
from starknet_py.net.account.account import Account, KeyPair
from starknet_py.net.models.chains import StarknetChainId
from starknet_py.transaction_errors import (
    TransactionNotReceivedError,
    TransactionRevertedError,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "signer_ids",
        "threshold",
        "expected_to_fail",
    ],
    [
        ([], 0, True),
        ([], 1, True),
        ([], 2, True),
        ([0], 0, False),
        ([0], 1, True),
        ([0], 2, True),
        ([0, 0], 0, False),
        ([0, 0], 1, True),
        ([0, 0], 2, False),
        ([0, 1], 0, False),
        ([0, 1], 1, True),
        ([0, 1], 2, False),
        ([0, 1, 2], 2, False),
    ],
    ids=[
        "signers_0_threshold_0",
        "signers_0_threshold_1",
        "signers_0_threshold_2",
        "signers_1_threshold_0",
        "signers_1_threshold_1",
        "signers_1_threshold_2",
        "signers_2_same_pubkey_threshold_0",
        "signers_2_same_pubkey_threshold_1",
        "signers_2_same_pubkey_threshold_2",
        "signers_2_threshold_0",
        "signers_2_threshold_1",
        "signers_2_threshold_2",
        "signers_3_threshold_2",
    ],
)
async def test_deployment(init_starknet, account_deployer_moa, signer_ids,
                          threshold, expected_to_fail):
    _, devnet_client, _ = init_starknet
    devnet_client: FullNodeClient

    try:
        account, _ = await account_deployer_moa(signer_ids, threshold)

        acc = Account(
            address=account.address,
            client=devnet_client,
            key_pair=KeyPair.from_private_key(ACCOUNTS[0].pk),
            chain=StarknetChainId.TESTNET,
        )
        assert await acc.cairo_version == 1, "wrong version"
        assert not expected_to_fail, "didn't fail"
    except TransactionRevertedError as e:
        assert expected_to_fail, "failed with valid params"


@pytest.mark.asyncio
async def test_deployment_with_duplicate_accounts(init_starknet,
                                                  account_declare_moa):
    (
        account_chash,
        account_sierra_str,
        signer_chash,
        signer_sierra_str,
    ) = account_declare_moa
    _, _, devnet_account = init_starknet
    devnet_account: Account

    signer_abi = json.loads(signer_sierra_str)["abi"]
    ext_acc = await utils_v2.deploy_external_account(devnet_account,
                                                     signer_chash, signer_abi,
                                                     ACCOUNTS[0].pubk)

    constructor_args = {"signers": [ext_acc, ext_acc], "threshold": 0}

    with pytest.raises((TransactionRevertedError, ClientError)):
        deploy_result = await Contract.deploy_contract(
            account=devnet_account,
            class_hash=account_chash,
            abi=json.loads(account_sierra_str)["abi"],
            constructor_args=constructor_args,
            max_fee=int(1e18),
            cairo_version=1,
        )
        await devnet_account.client.wait_for_tx(deploy_result.hash)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["is_v3"],
    [
        (False, ),
        (True, ),
    ],
    ids=[
        "v1",
        "v3",
    ],
)
@pytest.mark.asyncio
async def test_invoke_without_balance(init_starknet, account_deployer_moa,
                                      is_v3):
    _, devnet_client, _ = init_starknet
    account, signers_info = await account_deployer_moa([0], 0, top_up=False)

    signer = utils_v2.TestSigner(devnet_client, account, [ACCOUNTS[0].pk],
                                 signers_info)
    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)

    with pytest.raises(
            ClientError,
            match=
            'Client failed with code 54. Message: Account balance is smaller than'
    ):
        await signer.send_transactions(calls, is_v3=is_v3)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "signer_ids", "threshold", "sign_with_ids", "is_executed",
        "confirmations", "is_v3"
    ],
    [
        ([0], 0, [0], True, 1, False),
        ([0, 1], 0, [0], True, 1, False),
        ([0, 1], 0, [1], True, 1, False),
        ([0, 1], 2, [0], False, 1, False),
        ([0, 1], 2, [1], False, 1, False),
        ([0, 1], 2, [1, 0], True, 2, False),
        ([0, 1], 2, [0, 1], True, 2, False),
        ([0, 1, 2], 2, [0], False, 1, False),
        ([0, 1, 2], 2, [0, 1], True, 2, False),
        ([0, 1, 2], 2, [0, 1, 2], True, 3, False),
        ([0, 1, 2], 3, [0], False, 1, False),
        ([0, 1, 2], 3, [0, 1, 2], True, 3, False),
        ([0], 0, [0], True, 1, True),
        ([0, 1], 0, [0], True, 1, True),
        ([0, 1], 0, [1], True, 1, True),
        ([0, 1], 2, [0], False, 1, True),
        ([0, 1], 2, [1], False, 1, True),
        ([0, 1], 2, [1, 0], True, 2, True),
        ([0, 1], 2, [0, 1], True, 2, True),
        ([0, 1, 2], 2, [0], False, 1, True),
        ([0, 1, 2], 2, [0, 1], True, 2, True),
        ([0, 1, 2], 2, [0, 1, 2], True, 3, True),
        ([0, 1, 2], 3, [0], False, 1, True),
        ([0, 1, 2], 3, [0, 1, 2], True, 3, True),
    ],
    ids=[
        "signers_1_threshold_0_sign_0",
        "signers_2_threshold_0_sign_0",
        "signers_2_threshold_0_sign_1",
        "signers_2_threshold_2_sign_0",
        "signers_2_threshold_2_sign_1",
        "signers_2_threshold_2_sign_1_0",
        "signers_2_threshold_2_sign_0_1",
        "signers_3_threshold_2_sign_0",
        "signers_3_threshold_2_sign_0_1",
        "signers_3_threshold_2_sign_0_1_2",
        "signers_3_threshold_3_sign_0",
        "signers_3_threshold_3_sign_0_1_2",
        "signers_1_threshold_0_sign_0_v3",
        "signers_2_threshold_0_sign_0_v3",
        "signers_2_threshold_0_sign_1_v3",
        "signers_2_threshold_2_sign_0_v3",
        "signers_2_threshold_2_sign_1_v3",
        "signers_2_threshold_2_sign_1_0_v3",
        "signers_2_threshold_2_sign_0_1_v3",
        "signers_3_threshold_2_sign_0_v3",
        "signers_3_threshold_2_sign_0_1_v3",
        "signers_3_threshold_2_sign_0_1_2_v3",
        "signers_3_threshold_3_sign_0_v3",
        "signers_3_threshold_3_sign_0_1_2_v3",
    ],
)
async def test_invoke(prepare_signer, signer_ids, threshold, sign_with_ids,
                      is_executed, confirmations, is_v3):
    fee_contract_address = STRK_ADDRESS if is_v3 else FEE_CONTRACT_ADDRESS
    signer: TestSigner = await prepare_signer(signer_ids, threshold,
                                              signer_ids)
    balance_before = await signer.get_account(0).get_balance(
        fee_contract_address)

    transfer_amount = 10**8 + 1
    calls = utils_v2.get_transfer_calls(signer.address,
                                        ACCOUNTS[0].address,
                                        transfer_amount,
                                        is_v3=is_v3)
    if is_v3:
        resource_bounds = utils_v2.get_max_resource_bounds(is_executed)
        (_, res) = await signer.send_transactions(
            calls,
            signer_ids=sign_with_ids,
            l1_resource_bounds=resource_bounds,
            is_v3=True,
            proposer_id=sign_with_ids[0])
    else:
        fee = utils_v2.get_max_fee(is_executed)
        (_, res) = await signer.send_transactions(calls,
                                                  signer_ids=sign_with_ids,
                                                  max_fee=fee,
                                                  proposer_id=sign_with_ids[0])

    tx_hash = utils_v2.calculate_tx_hash(calls, signer.address,
                                         signer.get_guid(sign_with_ids[0]),
                                         len(sign_with_ids))
    check_pending_tx_event(res, tx_hash, confirmations, is_executed)

    balance_after = await signer.get_account(0).get_balance(
        fee_contract_address)
    balance_after += res.actual_fee.amount

    if is_executed:
        balance_after += transfer_amount
    assert balance_after == balance_before, "wrong balance"

    await utils_v2.get_and_check_multisig_tx_ex(signer.account, tx_hash,
                                                is_executed, confirmations)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["signer_ids", "threshold", "sign_with_ids", "is_v3", "expected_error"],
    [
        ([0, 1], 2, [0, 0], False, 'DUPLICATE_SIG'),
        ([0, 1, 2], 3, [0, 1], False, 'PENDING_WITH_MULTIPLE_SIG'),
        ([0, 1, 2], 3, [0, 1, 1], False, 'DUPLICATE_SIG'),
        ([0, 1], 2, [0, 0], True, 'DUPLICATE_SIG'),
        ([0, 1, 2], 3, [0, 1], True, 'PENDING_WITH_MULTIPLE_SIG'),
        ([0, 1, 2], 3, [0, 1, 1], True, 'DUPLICATE_SIG'),
    ],
    ids=[
        "signers_2_threshold_2_sign_0_0",
        "signers_3_threshold_3_sign_0_1",
        "signers_3_threshold_3_sign_0_1_1",
        "signers_2_threshold_2_sign_0_0_v3",
        "signers_3_threshold_3_sign_0_1_v3",
        "signers_3_threshold_3_sign_0_1_1_v3",
    ],
)
async def test_invoke_with_invalid_params(
    prepare_signer,
    signer_ids,
    threshold,
    sign_with_ids,
    is_v3,
    expected_error,
):
    signer: TestSigner = await prepare_signer(signer_ids, threshold,
                                              signer_ids)

    transfer_amount = 10**8 + 1
    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        transfer_amount)
    with pytest.raises(ClientError,
                       match=encode_string_as_hex(expected_error)):
        await signer.send_transactions(calls,
                                       signer_ids=sign_with_ids,
                                       is_v3=is_v3)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["is_v3"],
    [
        (False, ),
        (True, ),
    ],
    ids=[
        "v1",
        "v3",
    ],
)
async def test_try_invoke_with_missing_max_fee(prepare_simple_signer, is_v3):
    signer: TestSigner = prepare_simple_signer

    no_max_fee_calls = utils_v2.get_transfer_calls(signer.address,
                                                   ACCOUNTS[0].address,
                                                   10**8,
                                                   max_fee_eth=None,
                                                   signer_max_fee_eth=None,
                                                   max_fee_stark=None,
                                                   signer_max_fee_stark=None)
    with pytest.raises(ClientError,
                       match=encode_string_as_hex('INVALID_MAX_FEE')):
        await signer.send_transactions(no_max_fee_calls,
                                       signer_ids=[0],
                                       is_v3=is_v3)

    only_ex_eth_fee_calls = utils_v2.get_transfer_calls(
        signer.address,
        ACCOUNTS[0].address,
        10**8,
        max_fee_eth=10**18,
        signer_max_fee_eth=None,
        max_fee_stark=None,
        signer_max_fee_stark=None)
    with pytest.raises(ClientError,
                       match=encode_string_as_hex('INVALID_MAX_FEE')):
        await signer.send_transactions(only_ex_eth_fee_calls,
                                       signer_ids=[0],
                                       is_v3=is_v3)

    no_sign_max_fee_calls = utils_v2.get_transfer_calls(
        signer.address,
        ACCOUNTS[0].address,
        10**8,
        max_fee_eth=10**18,
        signer_max_fee_eth=10**19,
        max_fee_stark=None,
        signer_max_fee_stark=None)
    with pytest.raises(ClientError,
                       match=encode_string_as_hex('INVALID_MAX_FEE')):
        await signer.send_transactions(no_sign_max_fee_calls,
                                       signer_ids=[0],
                                       is_v3=is_v3)

    no_sign_strk_max_fee_calls = utils_v2.get_transfer_calls(
        signer.address,
        ACCOUNTS[0].address,
        10**8,
        max_fee_eth=10**18,
        signer_max_fee_eth=10**19,
        max_fee_stark=10**17,
        signer_max_fee_stark=None)
    with pytest.raises(ClientError,
                       match=encode_string_as_hex('INVALID_MAX_FEE')):
        await signer.send_transactions(no_sign_strk_max_fee_calls,
                                       signer_ids=[0],
                                       is_v3=is_v3)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["is_v3"],
    [
        (False, ),
        (True, ),
    ],
    ids=[
        "v1",
        "v3",
    ],
)
async def test_try_invoke_with_signing_max_fee_too_high(
        prepare_simple_signer, is_v3):
    signer: TestSigner = prepare_simple_signer
    if is_v3:
        calls = utils_v2.get_transfer_calls(
            signer.address,
            ACCOUNTS[0].address,
            10**8,
            MAX_EXECUTE_FEE_ETH,
            MAX_SIGN_FEE_ETH,
            MAX_EXECUTE_FEE_STRK,
            signer_max_fee_stark=MAX_SIGN_FEE_STRK * 1000,
            is_v3=is_v3)
    else:
        calls = utils_v2.get_transfer_calls(
            signer.address,
            ACCOUNTS[0].address,
            10**8,
            signer_max_fee_eth=MAX_SIGN_FEE_ETH * 10,
            is_v3=is_v3)

    with pytest.raises(ClientError,
                       match=encode_string_as_hex('INVALID_MAX_FEE')):
        await signer.send_transactions(calls, is_v3=is_v3)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["is_v3"],
    [
        (False, ),
        (True, ),
    ],
    ids=[
        "v1",
        "v3",
    ],
)
@pytest.mark.asyncio
async def test_try_replace_max_fee(prepare_signer, is_v3):
    signer: TestSigner = await prepare_signer([0, 1], 2, [0, 1])

    calls = utils_v2.get_transfer_calls(signer.address,
                                        ACCOUNTS[0].address,
                                        10**8,
                                        is_v3=is_v3)

    await signer.send_transactions(calls,
                                   signer_ids=[0],
                                   max_fee=MAX_SIGN_FEE_ETH,
                                   l1_resource_bounds=SIGNER_RESOURCE_BOUNDS,
                                   is_v3=is_v3)

    calls[0].calldata[0] = 10**17
    with pytest.raises(ClientError,
                       match=encode_string_as_hex('INVALID_TX_HASH')):
        await signer.send_transaction(
            to=signer.address,
            selector_name="sign_pending_multisig_transaction",
            calldata=utils_v2.prepare_calldata(signer.get_guid(0), 0, calls),
            signer_ids=[1],
            is_v3=is_v3,
            pending_calls=calls)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["is_v3"],
    [
        (False, ),
        (True, ),
    ],
    ids=[
        "v1",
        "v3",
    ],
)
async def test_try_exceed_executing_max_fee(prepare_signer, is_v3):
    signer: TestSigner = await prepare_signer([0, 1], 2, [0, 1])

    calls = utils_v2.get_transfer_calls(signer.address,
                                        ACCOUNTS[0].address,
                                        10**8,
                                        is_v3=is_v3)

    if is_v3:
        await signer.send_transactions(
            calls,
            signer_ids=[0],
            is_v3=True,
            l1_resource_bounds=SIGNER_RESOURCE_BOUNDS)
    else:
        await signer.send_transactions(calls,
                                       signer_ids=[0],
                                       max_fee=MAX_SIGN_FEE_ETH)

    with pytest.raises(ClientError,
                       match=encode_string_as_hex('MAX_FEE_TOO_HIGH')):
        if is_v3:
            await signer.send_transaction(
                to=signer.address,
                selector_name="sign_pending_multisig_transaction",
                calldata=utils_v2.prepare_calldata(signer.get_guid(0), 0,
                                                   calls),
                signer_ids=[1],
                is_v3=True,
                l1_resource_bounds=HIGH_EXECUTION_RESOURCE_BOUNDS,
                pending_calls=calls)
        else:
            await signer.send_transaction(
                to=signer.address,
                selector_name="sign_pending_multisig_transaction",
                calldata=utils_v2.prepare_calldata(signer.get_guid(0), 0,
                                                   calls),
                signer_ids=[1],
                max_fee=MAX_EXECUTE_FEE_ETH + 1,
                pending_calls=calls)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["is_v3"],
    [
        (False, ),
        (True, ),
    ],
    ids=[
        "v1",
        "v3",
    ],
)
async def test_try_exceed_executing_max_fee_on_first_call(
        prepare_signer, is_v3):
    signer: TestSigner = await prepare_signer([0, 1], 2, [0, 1])

    calls = utils_v2.get_transfer_calls(signer.address,
                                        ACCOUNTS[0].address,
                                        10**8,
                                        is_v3=is_v3)

    with pytest.raises(ClientError,
                       match=encode_string_as_hex('MAX_FEE_TOO_HIGH')):
        if is_v3:
            await signer.send_transactions(
                calls,
                signer_ids=[0, 1],
                is_v3=True,
                l1_resource_bounds=HIGH_EXECUTION_RESOURCE_BOUNDS)
        else:
            await signer.send_transactions(calls,
                                           signer_ids=[0, 1],
                                           max_fee=MAX_EXECUTE_FEE_ETH + 1)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["is_v3"],
    [
        (False, ),
        (True, ),
    ],
    ids=[
        "v1",
        "v3",
    ],
)
async def test_try_exceed_signing_max_fee_on_first_tx(prepare_signer, is_v3):
    signer: TestSigner = await prepare_signer([0, 1], 2, [0, 1])

    calls = utils_v2.get_transfer_calls(signer.address,
                                        ACCOUNTS[0].address,
                                        10**8,
                                        is_v3=is_v3)

    with pytest.raises(ClientError,
                       match=encode_string_as_hex('MAX_FEE_TOO_HIGH')):
        if is_v3:
            await signer.send_transactions(
                calls,
                signer_ids=[0],
                is_v3=True,
                l1_resource_bounds=HIGH_SIGNER_RESOURCE_BOUNDS)
        else:
            await signer.send_transactions(calls,
                                           signer_ids=[0],
                                           max_fee=MAX_SIGN_FEE_ETH + 1)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["is_v3"],
    [
        (False, ),
        (True, ),
    ],
    ids=[
        "v1",
        "v3",
    ],
)
async def test_try_exceed_signing_max_fee(prepare_signer, is_v3):
    signer: TestSigner = await prepare_signer([0, 1, 2], 3, [0, 1, 2])

    calls = utils_v2.get_transfer_calls(signer.address,
                                        ACCOUNTS[0].address,
                                        10**8,
                                        is_v3=is_v3)

    if is_v3:
        await signer.send_transactions(
            calls,
            signer_ids=[0],
            is_v3=True,
            l1_resource_bounds=SIGNER_RESOURCE_BOUNDS)
    else:
        await signer.send_transactions(calls,
                                       signer_ids=[0],
                                       max_fee=MAX_SIGN_FEE_ETH)

    with pytest.raises(ClientError,
                       match=encode_string_as_hex('MAX_FEE_TOO_HIGH')):
        if is_v3:
            await signer.send_transaction(
                to=signer.address,
                selector_name="sign_pending_multisig_transaction",
                calldata=utils_v2.prepare_calldata(signer.get_guid(0), 0,
                                                   calls),
                signer_ids=[1],
                is_v3=True,
                l1_resource_bounds=HIGH_SIGNER_RESOURCE_BOUNDS,
                pending_calls=calls)
        else:
            await signer.send_transaction(
                to=signer.address,
                selector_name="sign_pending_multisig_transaction",
                calldata=utils_v2.prepare_calldata(signer.get_guid(0), 0,
                                                   calls),
                signer_ids=[1],
                max_fee=MAX_SIGN_FEE_ETH + 1,
                pending_calls=calls)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "signer_ids",
        "threshold",
        "sign_with_ids",
    ],
    [
        ([1], 0, [0]),
        ([1, 2], 0, [0]),
        ([1, 2], 0, [0, 1]),
        ([1, 2], 0, [1, 0]),
        ([1, 2], 2, [1, 0]),
        ([1, 2, 3], 0, [1, 2, 0]),
    ],
    ids=[
        "signers_1_threshold_0_sign_0",
        "signers_2_threshold_0_sign_0",
        "signers_2_threshold_0_sign_0_1",
        "signers_2_threshold_0_sign_1_0",
        "signers_2_threshold_2_sign_1_0",
        "signers_3_threshold_0_sign_1_2_0",
    ],
)
async def test_try_invoke_with_invalid_signer(prepare_signer, signer_ids,
                                              threshold, sign_with_ids):
    signer: TestSigner = await prepare_signer(signer_ids, threshold,
                                              sign_with_ids)

    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)

    with pytest.raises(ClientError,
                       match=encode_string_as_hex('INVALID_SIGNATURE')):
        await signer.send_transactions(calls,
                                       signer_ids=list(
                                           range(0, len(sign_with_ids))))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "signer_ids",
        "threshold",
        "sign_with_ids",
        "sign_second",
        "is_executed",
        "confirmations",
    ],
    [
        ([0, 1], 2, [0], [1], True, 2),
        ([0, 1, 2], 3, [0], [1], False, 2),
        ([0, 1, 2], 2, [0], [1], True, 2),
    ],
    ids=[
        "signers_2_threshold_2_sign_0_sign_1",
        "signers_3_threshold_3_sign_0_sign_1",
        "signers_3_threshold_2_sign_0_sign_1",
    ],
)
async def test_sign_pending_multisig_transaction(
    prepare_signer,
    signer_ids,
    threshold,
    sign_with_ids,
    sign_second,
    is_executed,
    confirmations,
):
    signer: TestSigner = await prepare_signer(signer_ids, threshold,
                                              signer_ids)

    calls = utils_v2.get_transfer_calls(
        signer.address,
        ACCOUNTS[0].address,
        10**8,
    )

    (_, res) = await signer.send_transactions(calls,
                                              signer_ids=sign_with_ids,
                                              max_fee=MAX_SIGN_FEE_ETH,
                                              proposer_id=sign_with_ids[0])

    print(
        "addr ", await signer.client.get_storage_at(
            hex(signer.signers_info[sign_second[0]][0]),
            get_selector_from_name('pub_key')))
    print("pubkey ", signer.signers_info[sign_second[0]][1])

    tx_hash = utils_v2.calculate_tx_hash(
        calls,
        signer.address,
        signer.get_guid(sign_with_ids[0]),
        len(sign_with_ids),
    )
    check_pending_tx_event(res, tx_hash, len(sign_with_ids), False)

    await utils_v2.get_and_check_multisig_tx(signer.account, tx_hash,
                                             len(sign_with_ids))

    tx_fee = (MAX_EXECUTE_FEE_ETH if is_executed else MAX_SIGN_FEE_ETH
              )  # fee is limited for non-executing tx
    (_, res2) = await signer.send_transaction(
        to=signer.address,
        selector_name="sign_pending_multisig_transaction",
        calldata=utils_v2.prepare_calldata(signer.get_guid(sign_with_ids[0]),
                                           0, calls),
        signer_ids=sign_second,
        max_fee=tx_fee,
        proposer_id=sign_with_ids[0],
        pending_calls=calls,
    )

    check_pending_tx_event(res2, tx_hash, confirmations - len(sign_with_ids),
                           is_executed)

    await utils_v2.get_and_check_multisig_tx_ex(signer.account, tx_hash,
                                                is_executed, confirmations)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "signer_ids", "threshold", "sign_with_ids", "sign_second",
        "is_executed", "expected_error"
    ],
    [
        ([0, 1], 2, [0], [0], False, 'ALREADY_CONFIRMED'),
        ([0, 1, 2], 3, [0, 1], [1], False, 'PENDING_WITH_MULTIPLE_SIG'),
        ([0, 1, 2], 3, [0], [0, 1], False, 'INVALID_SIGNATURE'),
        ([0, 1, 2], 3, [0], [0, 1, 2], True, 'INVALID_SIGNATURE'),
        ([0, 1, 2], 3, [0, 1], [2], True, 'PENDING_WITH_MULTIPLE_SIG'),
        ([0, 1, 2], 3, [0], [1, 2], True, 'INVALID_SIGNATURE'),
    ],
    ids=[
        "signers_2_threshold_2_sign_0_sign_0",
        "signers_3_threshold_3_sign_0_1_sign_1",
        "signers_3_threshold_3_sign_0_sign_0_1",
        "signers_3_threshold_3_sign_0_sign_0_1_2",
        "signers_3_threshold_3_sign_0_1_sign_2",
        "signers_3_threshold_3_sign_0_sign_1_2",
    ],
)
async def test_sign_pending_multisig_transaction_with_invalid_params(
        prepare_signer, signer_ids, threshold, sign_with_ids, sign_second,
        is_executed, expected_error):
    signer: TestSigner = await prepare_signer(signer_ids, threshold,
                                              signer_ids)

    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)

    with pytest.raises(ClientError,
                       match=encode_string_as_hex(expected_error)):
        await signer.send_transactions(calls,
                                       signer_ids=sign_with_ids,
                                       max_fee=MAX_SIGN_FEE_ETH)

        tx_fee = (MAX_EXECUTE_FEE_ETH if is_executed else MAX_SIGN_FEE_ETH
                  )  # fee is limited for non-executing tx
        await signer.send_transaction(
            to=signer.address,
            selector_name="sign_pending_multisig_transaction",
            calldata=utils_v2.prepare_calldata(
                signer.get_guid(sign_with_ids[0]), 0, calls),
            signer_ids=sign_second,
            max_fee=tx_fee,
            proposer_id=sign_with_ids[0],
            pending_calls=calls,
        )


@pytest.mark.asyncio
async def test_execute_pending_in_third_tx(prepare_signer):
    signer: TestSigner = await prepare_signer([0, 1, 2], 3, [0, 1, 2])

    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)

    (_, res1) = await signer.send_transactions(calls,
                                               signer_ids=[0],
                                               max_fee=MAX_SIGN_FEE_ETH)
    tx_hash = utils_v2.calculate_tx_hash(calls, signer.address,
                                         signer.get_guid(0), 1)
    check_pending_tx_event(res1, tx_hash, 1, False)
    await utils_v2.get_and_check_multisig_tx(signer.account, tx_hash, 1)

    (_, res2) = await signer.send_transaction(
        to=signer.address,
        selector_name="sign_pending_multisig_transaction",
        calldata=utils_v2.prepare_calldata(signer.get_guid(0), 0, calls),
        signer_ids=[1],
        max_fee=MAX_SIGN_FEE_ETH,
        pending_calls=calls,
    )
    check_pending_tx_event(res2, tx_hash, 1, False)
    await utils_v2.get_and_check_multisig_tx(signer.account, tx_hash, 2)

    (_, res3) = await signer.send_transaction(
        to=signer.address,
        selector_name="sign_pending_multisig_transaction",
        calldata=utils_v2.prepare_calldata(signer.get_guid(0), 0, calls),
        signer_ids=[2],
        max_fee=MAX_EXECUTE_FEE_ETH,
        pending_calls=calls,
    )
    check_pending_tx_event(res3, tx_hash, 1, True)
    await utils_v2.get_and_check_multisig_tx(signer.account, 0, 0)


@pytest.mark.asyncio
async def test_try_sign_pending_with_same_signer_twice(prepare_signer):
    signer: TestSigner = await prepare_signer([0, 1, 2, 3], 4, [0, 1, 2, 3])

    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)

    (_, res1) = await signer.send_transactions(calls,
                                               signer_ids=[1],
                                               max_fee=MAX_SIGN_FEE_ETH,
                                               proposer_id=1)
    tx_hash = utils_v2.calculate_tx_hash(calls, signer.address,
                                         signer.get_guid(1), 1)
    check_pending_tx_event(res1, tx_hash, 1, False)
    await utils_v2.get_and_check_multisig_tx(signer.account, tx_hash, 1)

    with pytest.raises(ClientError,
                       match=encode_string_as_hex('ALREADY_CONFIRMED')):
        await signer.send_transaction(
            to=signer.address,
            selector_name="sign_pending_multisig_transaction",
            calldata=utils_v2.prepare_calldata(signer.get_guid(1), 0, calls),
            signer_ids=[1],
            max_fee=MAX_EXECUTE_FEE_STRK,
            proposer_id=1,
            pending_calls=calls,
        )


@pytest.mark.asyncio
async def test_sign_executed_tx(prepare_signer):
    signer: TestSigner = await prepare_signer([0, 1, 2], 2, [0, 1, 2])

    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)

    await signer.send_transactions(calls,
                                   signer_ids=[0],
                                   max_fee=MAX_SIGN_FEE_ETH)
    tx_hash = utils_v2.calculate_tx_hash(calls, signer.address,
                                         signer.get_guid(0), 1)
    await utils_v2.get_and_check_multisig_tx(signer.account, tx_hash, 1)

    await signer.send_transaction(
        to=signer.address,
        selector_name="sign_pending_multisig_transaction",
        calldata=utils_v2.prepare_calldata(signer.get_guid(0), 0, calls),
        signer_ids=[1],
        max_fee=MAX_EXECUTE_FEE_ETH,
        pending_calls=calls,
    )
    await utils_v2.get_and_check_multisig_tx(signer.account, 0, 0)

    with pytest.raises(ClientError,
                       match=encode_string_as_hex('INVALID_TX_HASH')):
        await signer.send_transaction(
            to=signer.address,
            selector_name="sign_pending_multisig_transaction",
            calldata=utils_v2.prepare_calldata(signer.get_guid(0), 0, calls),
            signer_ids=[2],
            max_fee=MAX_EXECUTE_FEE_ETH,
            pending_calls=calls,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "nonce",
        "fee_calls",
    ],
    [
        (0, 10**9),
        (1, 10**8),
        (1, 10**9),
    ],
    ids=[
        "invalid_fee_in_calls",
        "invalid_nonce",
        "invalid_all",
    ],
)
async def test_sign_invalid_tx(prepare_signer, nonce, fee_calls):
    signer: TestSigner = await prepare_signer([0, 1, 2], 3, [0, 1, 2])

    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)

    await signer.send_transactions(calls,
                                   signer_ids=[0],
                                   max_fee=MAX_SIGN_FEE_ETH)
    tx_hash = utils_v2.calculate_tx_hash(calls, signer.address,
                                         signer.get_guid(0), 1)
    await utils_v2.get_and_check_multisig_tx(signer.account, tx_hash, 1)

    calls2 = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                         fee_calls, MAX_EXECUTE_FEE_ETH,
                                         MAX_SIGN_FEE_ETH,
                                         MAX_EXECUTE_FEE_STRK,
                                         MAX_SIGN_FEE_STRK)

    with pytest.raises(ClientError,
                       match=encode_string_as_hex('INVALID_TX_HASH')):
        await signer.send_transaction(
            to=signer.address,
            selector_name="sign_pending_multisig_transaction",
            calldata=utils_v2.prepare_calldata(signer.get_guid(0), nonce,
                                               calls2),
            signer_ids=[1],
            max_fee=MAX_EXECUTE_FEE_ETH,
            pending_nonce=nonce,
            pending_calls=calls)


@pytest.mark.asyncio
async def test_sign_without_pending(prepare_signer):
    signer: TestSigner = await prepare_signer([0, 1, 2], 3, [0, 1, 2])

    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)

    with pytest.raises(ClientError,
                       match=encode_string_as_hex('INVALID_TX_HASH')):
        await signer.send_transaction(
            to=signer.address,
            selector_name="sign_pending_multisig_transaction",
            calldata=utils_v2.prepare_calldata(signer.get_guid(0), 0, calls),
            signer_ids=[1],
            max_fee=MAX_SIGN_FEE_ETH,
            pending_calls=calls,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "deploy_signer_ids",
        "signer_ids",
        "threshold",
        "sign_with_ids",
    ],
    [
        ([0, 1], [0, 2], 2, [1]),
        ([0, 1], [0, 2], 2, [0, 1]),
        ([0, 1, 3], [0, 1, 2], 2, [2]),
        ([0, 1, 2], [0, 1, 3], 3, [2]),
        ([0, 1, 2], [0, 3, 2], 3, [1]),
        ([0, 1, 2], [0, 3, 2], 3, [1, 2]),
        ([0, 1, 2], [0, 2, 3], 3, [1, 2]),
        ([0, 1, 2], [0, 2, 3], 2, [1, 2]),
    ],
    ids=[
        "signers_2_threshold_2_sign_1",
        "signers_2_threshold_2_sign_0_1",
        "signers_2_threshold_2_sign_2",
        "signers_3_threshold_3_sign_2",
        "signers_3_threshold_3_sign_1",
        "signers_3_threshold_3_sign_1_2",
        "signers_3_threshold_3_sign_1_2_reverse",
        "signers_3_threshold_2_sign_1_2",
    ],
)
async def test_sign_pending_with_invalid_signer(
    prepare_signer,
    deploy_signer_ids,
    signer_ids,
    threshold,
    sign_with_ids,
):
    signer: TestSigner = await prepare_signer(deploy_signer_ids, threshold,
                                              signer_ids)

    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)

    await signer.send_transactions(calls,
                                   signer_ids=[0],
                                   max_fee=MAX_SIGN_FEE_ETH)
    tx_hash = utils_v2.calculate_tx_hash(calls, signer.address,
                                         signer.get_guid(0), 1)
    await utils_v2.get_and_check_multisig_tx(signer.account, tx_hash, 1)

    with pytest.raises(ClientError,
                       match=encode_string_as_hex('INVALID_SIGNATURE')):
        await signer.send_transaction(
            to=signer.address,
            selector_name="sign_pending_multisig_transaction",
            calldata=utils_v2.prepare_calldata(signer.get_guid(0), 0, calls),
            signer_ids=sign_with_ids,
            max_fee=MAX_SIGN_FEE_ETH,
            pending_calls=calls,
        )


@pytest.mark.asyncio
async def test_sign_with_duplicate_signers_in_one_tx(prepare_signer):
    signer: TestSigner = await prepare_signer([0, 1], 2, [0, 1])

    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)

    with pytest.raises(ClientError,
                       match=encode_string_as_hex('DUPLICATE_SIG')):
        await signer.send_transactions(calls,
                                       signer_ids=[0, 0],
                                       max_fee=MAX_EXECUTE_FEE_ETH)


@pytest.mark.asyncio
async def test_sign_with_duplicate_signers_in_two_tx(prepare_signer):
    signer: TestSigner = await prepare_signer([0, 1], 2, [0, 1])

    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)

    await signer.send_transactions(calls,
                                   signer_ids=[0],
                                   max_fee=MAX_SIGN_FEE_ETH)
    tx_hash = utils_v2.calculate_tx_hash(calls, signer.address,
                                         signer.get_guid(0), 1)
    await utils_v2.get_and_check_multisig_tx(signer.account, tx_hash, 1)

    with pytest.raises(ClientError,
                       match=encode_string_as_hex('ALREADY_CONFIRMED')):
        await signer.send_transaction(
            to=signer.address,
            selector_name="sign_pending_multisig_transaction",
            calldata=utils_v2.prepare_calldata(signer.get_guid(0), 0, calls),
            signer_ids=[0],
            max_fee=MAX_SIGN_FEE_ETH,
            pending_calls=calls,
        )


@pytest.mark.asyncio
async def test_estimate_fee_allow_different_pending_hash(prepare_signer):
    signer: TestSigner = await prepare_signer([0, 1, 2], 3, [0, 1, 2])

    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)

    (_, res) = await signer.send_transactions(calls,
                                              signer_ids=[0],
                                              max_fee=MAX_SIGN_FEE_ETH)

    tx_hash = utils_v2.calculate_tx_hash(calls, signer.address,
                                         signer.get_guid(0), 1)
    check_pending_tx_event(res, tx_hash, 1, False)

    await utils_v2.get_and_check_multisig_tx(signer.account, tx_hash, 1)

    calls[1].calldata[0] = ACCOUNTS[1].address

    fee = await signer.estimate_fee(
        to=signer.address,
        selector_name="sign_pending_multisig_transaction",
        calldata=utils_v2.prepare_calldata(signer.get_guid(0), 0, calls),
        signer_ids=[1],
    )

    with pytest.raises(ClientError,
                       match=encode_string_as_hex('INVALID_TX_HASH')):
        await signer.send_transaction(
            to=signer.address,
            selector_name="sign_pending_multisig_transaction",
            calldata=utils_v2.prepare_calldata(signer.get_guid(0), 0, calls),
            signer_ids=[0],
            max_fee=fee.overall_fee,
            pending_calls=calls,
        )


@pytest.mark.asyncio
async def test_estimate_fee_allow_invalid_sig(prepare_signer):
    signer: TestSigner = await prepare_signer([0, 1, 2], 3, [0, 1, 2])

    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)

    invoke = await signer.signers[0]._prepare_invoke(
        calls,
        nonce=0,
        max_fee=0,
    )
    invoke.signature.extend([0, 0, 0, 0, 0, 1, 0])
    await signer.client.estimate_fee(invoke)
