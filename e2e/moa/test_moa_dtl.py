import e2e.utils.utils_v2 as utils_v2
from e2e.utils.utils_v2 import TestSigner, check_pending_tx_event, MAX_EXECUTE_FEE_ETH, MAX_SIGN_FEE_ETH, MAX_EXECUTE_FEE_STRK, MAX_SIGN_FEE_STRK, TestSigner, check_pending_tx_event, STRK_ADDRESS, EXECUTION_RESOURCE_BOUNDS, SIGNER_RESOURCE_BOUNDS, HIGH_EXECUTION_RESOURCE_BOUNDS, HIGH_SIGNER_RESOURCE_BOUNDS
from e2e.utils.fixtures_moa import *

import pytest

from starknet_py.transaction_errors import (
    TransactionNotReceivedError,
    TransactionRevertedError,
)
from starknet_py.net.http_client import ClientError

DTL = 24


@pytest.mark.asyncio
async def test_daily_transaction_limit(prepare_signer):
    signer: TestSigner = await prepare_signer([0, 1], 0, [0, 1])
    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)
    for i in range(DTL):
        await signer.send_transactions(calls, signer_ids=[0], pending_nonce=i)

    # signer 0 exceeded the limit
    with pytest.raises((TransactionNotReceivedError, ClientError)):
        await signer.send_transactions(calls,
                                       signer_ids=[0],
                                       pending_nonce=DTL)
    utils_v2.validate_tx_limit(signer, 0, DTL)

    # signer 1 is fine
    await signer.send_transactions(calls,
                                   signer_ids=[1],
                                   proposer_id=1,
                                   pending_nonce=DTL)
    utils_v2.validate_tx_limit(signer, 1, 0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "signer_ids",
        "threshold",
        "sign_with_ids",
        "sign_second",
    ],
    [
        ([0, 1, 2], 2, [0], [2]),
        ([0, 1, 2], 2, [1], [2]),
    ],
    ids=[
        "signers_3_threshold_2_sign_0_sign_2",
        "signers_3_threshold_2_sign_1_sign_2",
    ],
)
async def test_dtl_with_execute_txn(
    prepare_signer,
    signer_ids,
    threshold,
    sign_with_ids,
    sign_second,
):
    signer: TestSigner = await prepare_signer(signer_ids, threshold,
                                              signer_ids)
    for i in range(DTL):
        calls = utils_v2.get_transfer_calls(signer.address,
                                            ACCOUNTS[0].address, 10**8)

        (_, res) = await signer.send_transactions(calls,
                                                  signer_ids=sign_with_ids,
                                                  max_fee=MAX_SIGN_FEE_ETH,
                                                  proposer_id=sign_with_ids[0],
                                                  pending_nonce=i * 2)

        tx_hash = utils_v2.calculate_tx_hash(calls,
                                             signer.address,
                                             signer.get_guid(sign_with_ids[0]),
                                             1,
                                             nonce=i * 2)
        check_pending_tx_event(res, tx_hash, len(sign_with_ids), False)

        await utils_v2.get_and_check_multisig_tx(signer.account, tx_hash,
                                                 len(sign_with_ids))
        (_, res2) = await signer.send_transaction(
            to=signer.address,
            selector_name="sign_pending_multisig_transaction",
            calldata=utils_v2.prepare_calldata(
                signer.get_guid(sign_with_ids[0]), i * 2, calls),
            signer_ids=sign_second,
            max_fee=MAX_SIGN_FEE_ETH,
            proposer_id=sign_with_ids[0],
            pending_nonce=i * 2,
            pending_calls=calls)
        check_pending_tx_event(res2, tx_hash, len(sign_second), True)

        await utils_v2.get_and_check_multisig_tx(signer.account, 0, 0)

    with pytest.raises((TransactionNotReceivedError, ClientError)):
        await signer.send_transactions(calls,
                                       signer_ids=sign_second,
                                       max_fee=MAX_SIGN_FEE_ETH,
                                       proposer_id=sign_second[0],
                                       pending_nonce=DTL)

    utils_v2.validate_tx_limit(signer, sign_second[0], DTL)


@pytest.mark.asyncio
async def test_dtl_with_validate_txn(prepare_signer):
    signer: TestSigner = await prepare_signer([0, 1, 2], 3, [0, 1, 2])

    for i in range(DTL):
        calls = utils_v2.get_transfer_calls(signer.address,
                                            ACCOUNTS[0].address, 10**8)

        (_, res) = await signer.send_transactions(calls,
                                                  signer_ids=[1],
                                                  max_fee=MAX_SIGN_FEE_ETH,
                                                  proposer_id=1,
                                                  pending_nonce=i)

        tx_hash = utils_v2.calculate_tx_hash(calls,
                                             signer.address,
                                             signer.get_guid(1),
                                             1,
                                             nonce=i)

        # txn validated, but not executed
        check_pending_tx_event(res, tx_hash, 1, False)
        await utils_v2.get_and_check_multisig_tx(signer.account, tx_hash, 1)

    # signer 1 exceeded the limit
    with pytest.raises((TransactionNotReceivedError, ClientError)):
        await signer.send_transactions(calls,
                                       signer_ids=[1],
                                       proposer_id=1,
                                       pending_nonce=DTL)

    utils_v2.validate_tx_limit(signer, 1, DTL)


@pytest.mark.asyncio
async def test_dtl_reset_on_next_day(prepare_signer, init_starknet):
    devnet_url, _, _ = init_starknet
    signer: TestSigner = await prepare_signer([0, 1], 0, [0, 1])

    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)
    for i in range(DTL):
        await signer.send_transactions(calls, signer_ids=[0], pending_nonce=i)

    # signer 0 exceeded the limit
    with pytest.raises((TransactionNotReceivedError, ClientError)):
        await signer.send_transactions(calls,
                                       signer_ids=[0],
                                       pending_nonce=DTL)

    # but the next day txn_count = 0
    utils_v2.increase_devnet_days(devnet_url, 1)
    await signer.send_transactions(calls, signer_ids=[0], pending_nonce=DTL)


@pytest.mark.asyncio
async def test_dtl_with_reverted_tx(prepare_signer):
    signer: TestSigner = await prepare_signer([0, 1], 0, [0, 1])

    invalid_call = utils_v2.get_transfer_calls(signer.address,
                                               ACCOUNTS[0].address, 10**28)
    for _ in range(DTL):
        with pytest.raises((TransactionRevertedError, ClientError)):
            await signer.send_transactions(invalid_call, signer_ids=[0])
    utils_v2.validate_tx_limit(signer, 0, DTL)

    valid_calls = utils_v2.get_transfer_calls(
        signer.address, ACCOUNTS[0].address, 1, MAX_EXECUTE_FEE_ETH,
        MAX_SIGN_FEE_ETH, MAX_EXECUTE_FEE_STRK, MAX_SIGN_FEE_STRK)

    with pytest.raises((TransactionNotReceivedError, ClientError)):
        await signer.send_transactions(valid_calls, signer_ids=[0])


@pytest.mark.asyncio
async def test_dtl_with_not_validated_tx(prepare_signer):
    signer: TestSigner = await prepare_signer([0, 1], 0, [0, 1])

    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)
    with pytest.raises((TransactionNotReceivedError, ClientError)):
        await signer.send_transactions(calls, signer_ids=[0, 0])
    utils_v2.validate_tx_limit(signer, 0, 0)


@pytest.mark.asyncio
async def test_get_tx_count(prepare_simple_signer, init_starknet):
    devnet_url, _, _ = init_starknet

    signer: TestSigner = prepare_simple_signer
    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)

    # 4 days later
    utils_v2.increase_devnet_days(devnet_url, 4)
    for i in range(6):
        await signer.send_transactions(calls, pending_nonce=i)

    # another 3 days later, 7 in total
    utils_v2.increase_devnet_days(devnet_url, 3)
    for i in range(8):
        await signer.send_transactions(calls, pending_nonce=i + 6)

    utils_v2.validate_tx_limit(signer, 0, 6, 4)
    utils_v2.validate_tx_limit(signer, 0, 8, 7)
    utils_v2.validate_tx_limit(signer, 0, 0, 20)
