from e2e.utils.utils import *
from e2e.utils.fixtures import *

import pytest
import requests
import time
import random

from poseidon_py.poseidon_hash import poseidon_hash_many
from starknet_py.constants import FEE_CONTRACT_ADDRESS
from starknet_py.net.account.account import Account
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
    assert_required_signer,
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

    await assert_required_signer(account, deferred_remove_call,
                                 REQUIRED_SIGNER_STARK)
    await assert_required_signer(
        account, add_secp256r1_call, REQUIRED_SIGNER_MULTISIG
        if multisig_threshold == 2 else REQUIRED_SIGNER_STRONG)

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
