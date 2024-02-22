from e2e.utils.utils import *
from e2e.utils.fixtures import *

from collections import namedtuple
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
from starknet_py.hash.address import compute_address
from starknet_py.hash.selector import get_selector_from_name
from starknet_py.net.models.chains import StarknetChainId


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
