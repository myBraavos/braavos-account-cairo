from e2e.utils.utils import *
from e2e.utils.fixtures import *

import pytest
import random

from poseidon_py.poseidon_hash import poseidon_hash_many
from starknet_py.constants import FEE_CONTRACT_ADDRESS
from starknet_py.net.account.account import Account, KeyPair
from starknet_py.net.client_models import (
    Call,
    TransactionExecutionStatus,
)
from starknet_py.net.full_node_client import FullNodeClient
from starknet_py.hash.selector import get_selector_from_name


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
    exec_txn = await account.execute_v1(
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
    exec_txn = await account.execute_v1(
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
    exec_txn = await account.execute_v1(
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

    exec_txn = await account.execute_v1(
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
    exec_txn = await account.execute_v1(
        calls=balanceof_call,
        max_fee=int(0.1 * 10**18),
    )
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    assert res.execution_status == TransactionExecutionStatus.SUCCEEDED, "failed executing with stark signer"

    if webauthn_secp256r1_signer is None:
        account.signer = create_legacy_stark_signer(stark_privk)
        exec_txn = await account.execute_v1(
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
    exec_txn = await account.execute_v1(
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

    exec_txn = await account.execute_v1(
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
    exec_txn = await account.execute_v1(
        calls=balanceof_call,
        max_fee=int(0.1 * 10**18),
    )
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    assert res.execution_status == TransactionExecutionStatus.SUCCEEDED, "failed executing with stark signer"

    if hws_secp256r1_signer is None:
        account.signer = create_legacy_stark_signer(stark_privk)
        exec_txn = await account.execute_v1(
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
    exec_txn = await account.execute_v1(
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
        exec_txn = await account.execute_v1(
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
    exec_txn = await account.execute_v1(
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

    exec_txn = await account.execute_v1(
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
    exec_txn = await account.execute_v1(
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
        exec_txn = await account.execute_v1(
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

    exec_txn = await account.execute_v1(
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

    exec_txn = await account.execute_v1(
        calls=balanceof_call,
        max_fee=int(0.1 * 10**18),
    )
    res = await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    assert res.execution_status == TransactionExecutionStatus.SUCCEEDED, "unexpected failed execution"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "multisig_threshold",
        "signers_num",
        "signers_type",
    ],
    [
        (2, 2, SECP256R1_SIGNER_TYPE),
        (2, 3, SECP256R1_SIGNER_TYPE),
        (3, 3, SECP256R1_SIGNER_TYPE),
        (2, 4, SECP256R1_SIGNER_TYPE),
        (3, 4, SECP256R1_SIGNER_TYPE),
        (4, 4, SECP256R1_SIGNER_TYPE),
        (5, 10, SECP256R1_SIGNER_TYPE),
        (2, 2, WEBAUTHN_SIGNER_TYPE),
        (2, 3, WEBAUTHN_SIGNER_TYPE),
        (3, 3, WEBAUTHN_SIGNER_TYPE),
        (2, 4, WEBAUTHN_SIGNER_TYPE),
        (3, 4, WEBAUTHN_SIGNER_TYPE),
        (4, 4, WEBAUTHN_SIGNER_TYPE),
        (5, 10, WEBAUTHN_SIGNER_TYPE),
    ],
    ids=[
        "threshold_2_signers_2_secp256r1",
        "threshold_2_signers_3_secp256r1",
        "threshold_3_signers_3_secp256r1",
        "threshold_2_signers_4_secp256r1",
        "threshold_3_signers_4_secp256r1",
        "threshold_4_signers_4_secp256r1",
        "threshold_5_signers_10_secp256r1",
        "threshold_2_signers_2_webauthn",
        "threshold_2_signers_3_webauthn",
        "threshold_3_signers_3_webauthn",
        "threshold_2_signers_4_webauthn",
        "threshold_3_signers_4_webauthn",
        "threshold_4_signers_4_webauthn",
        "threshold_5_signers_10_webauthn",
    ],
)
async def test_add_secp256r1_signer_m_of_n(
    init_starknet,
    account_deployer,
    multisig_threshold,
    signers_num,
    signers_type,
):
    _, devnet_client, _ = init_starknet
    devnet_client: GatewayClient
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account

    signers = []
    for i in range(signers_num - 1):
        secp256r1_keypair = generate_secp256r1_keypair()
        secp256r1_pubk = flatten_seq(secp256r1_keypair[1])

        # set threshold when adding last signer
        threshold = 0 if i < signers_num - 2 else multisig_threshold

        add_secp256r1_call = Call(
            to_addr=account.address,
            selector=get_selector_from_name("add_secp256r1_signer"),
            calldata=[*secp256r1_pubk, signers_type, threshold],
        )
        exec_txn = await account.execute_v1(
            calls=add_secp256r1_call,
            max_fee=10**17,
        )
        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

        signer = (create_secp256r1_signer(secp256r1_keypair[0])
                  if signers_type == SECP256R1_SIGNER_TYPE else
                  create_webauthn_signer(secp256r1_keypair[0]))
        account.signer = signer
        signers.append(signer)

    balanceof_call = Call(
        to_addr=int(FEE_CONTRACT_ADDRESS, 16),
        selector=get_selector_from_name("balanceOf"),
        calldata=[account.address],
    )
    stark_signer = create_stark_signer(stark_privk)

    under_threshold = create_multisig_signers(
        [stark_signer, *signers[:multisig_threshold - 2]])
    await assert_execute_fails_with_signer(
        account,
        balanceof_call,
        under_threshold,
        "INVALID_SIG",
    )

    # sig num = threshold
    account.signer = create_multisig_signers(
        [stark_signer, *signers[:multisig_threshold - 1]])
    await execute_calls(account, balanceof_call, max_fee=10**16)

    if multisig_threshold <= len(signers):
        # sig num > threshold
        account.signer = create_multisig_signers(
            [stark_signer, *signers[:multisig_threshold]])
        await execute_calls(account, balanceof_call, max_fee=10**16)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "multisig_threshold",
        "signers_types",
    ],
    [
        (2, [SECP256R1_SIGNER_TYPE, WEBAUTHN_SIGNER_TYPE]),
        (2, [WEBAUTHN_SIGNER_TYPE, SECP256R1_SIGNER_TYPE]),
        (2,
         [SECP256R1_SIGNER_TYPE, WEBAUTHN_SIGNER_TYPE, WEBAUTHN_SIGNER_TYPE]),
        (2,
         [WEBAUTHN_SIGNER_TYPE, SECP256R1_SIGNER_TYPE, SECP256R1_SIGNER_TYPE]),
        (3,
         [SECP256R1_SIGNER_TYPE, WEBAUTHN_SIGNER_TYPE, WEBAUTHN_SIGNER_TYPE]),
        (3,
         [WEBAUTHN_SIGNER_TYPE, SECP256R1_SIGNER_TYPE, SECP256R1_SIGNER_TYPE]),
        (
            3,
            [
                SECP256R1_SIGNER_TYPE,
                WEBAUTHN_SIGNER_TYPE,
                WEBAUTHN_SIGNER_TYPE,
                SECP256R1_SIGNER_TYPE,
                SECP256R1_SIGNER_TYPE,
            ],
        ),
        (
            3,
            [
                WEBAUTHN_SIGNER_TYPE,
                SECP256R1_SIGNER_TYPE,
                SECP256R1_SIGNER_TYPE,
                WEBAUTHN_SIGNER_TYPE,
                WEBAUTHN_SIGNER_TYPE,
            ],
        ),
        (
            4,
            [
                SECP256R1_SIGNER_TYPE,
                WEBAUTHN_SIGNER_TYPE,
                WEBAUTHN_SIGNER_TYPE,
                SECP256R1_SIGNER_TYPE,
                SECP256R1_SIGNER_TYPE,
            ],
        ),
        (
            4,
            [
                WEBAUTHN_SIGNER_TYPE,
                SECP256R1_SIGNER_TYPE,
                SECP256R1_SIGNER_TYPE,
                WEBAUTHN_SIGNER_TYPE,
                WEBAUTHN_SIGNER_TYPE,
            ],
        ),
    ],
    ids=[
        "threshold_2_signers_2_s_w",
        "threshold_2_signers_2_w_s",
        "threshold_2_signers_3_s_w_w",
        "threshold_2_signers_3_w_s_s",
        "threshold_3_signers_3_s_w_w",
        "threshold_3_signers_3_w_s_s",
        "threshold_3_signers_5_s_w_w_s_s",
        "threshold_3_signers_5_w_s_s_w_w",
        "threshold_4_signers_5_s_w_w_s_s",
        "threshold_4_signers_5_w_s_s_w_w",
    ],
)
async def test_secp256r1_and_webauthn_signers_m_of_n(
    init_starknet,
    account_deployer,
    multisig_threshold,
    signers_types,
):
    _, devnet_client, _ = init_starknet
    devnet_client: GatewayClient
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account

    signers = []
    await add_signers(signers_types, multisig_threshold, account,
                      devnet_client, signers)

    balanceof_call = Call(
        to_addr=int(FEE_CONTRACT_ADDRESS, 16),
        selector=get_selector_from_name("balanceOf"),
        calldata=[account.address],
    )

    under_threshold = create_multisig_signers(signers[:multisig_threshold - 1])
    await assert_execute_fails_with_signer(
        account,
        balanceof_call,
        under_threshold,
        "INVALID_SIG",
    )

    # sig num = threshold
    account.signer = create_multisig_signers(signers[:multisig_threshold])
    await execute_calls(account, balanceof_call, max_fee=10**16)

    if multisig_threshold < len(signers):
        # sig num > threshold
        account.signer = create_multisig_signers(signers[:multisig_threshold +
                                                         1])
        await execute_calls(account, balanceof_call, max_fee=10**16)
