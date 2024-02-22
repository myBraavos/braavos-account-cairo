from e2e.utils.utils import *
from e2e.utils.fixtures import *

import pytest
import random

from starknet_py.constants import FEE_CONTRACT_ADDRESS
from starknet_py.net.account.account import Account
from starknet_py.net.client_models import Call
from starknet_py.net.full_node_client import FullNodeClient
from starknet_py.hash.selector import get_selector_from_name


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
    assert_required_signer_of_bypass_call,
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
    await assert_required_signer_of_bypass_call(account,
                                                REQUIRED_SIGNER_STARK,
                                                amount=int(0.999999 * 10**18))

    await assert_required_signer_of_bypass_call(
        account,
        REQUIRED_SIGNER_MULTISIG
        if multisig_threshold == 2 else REQUIRED_SIGNER_STRONG,
        amount=int(1.000001 * 10**18))


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

    max_fee = int(0.0001 * 10**18)
    invoke_txn = await account.sign_invoke_v1_transaction(balanceof_call,
                                                          max_fee=max_fee)
    invoke_est_fee = await account.sign_for_fee_estimate(invoke_txn)
    await devnet_client.estimate_fee(invoke_est_fee)

    invoke_txn_v3 = await account.sign_invoke_v3_transaction(
        balanceof_call,
        l1_resource_bounds=ResourceBounds(
            max_amount=int(max_fee / (100 * 10**9)),
            max_price_per_unit=100 * 10**9 + 1,
        ),
    )
    invoke_est_fee_v3 = await account.sign_for_fee_estimate(invoke_txn_v3)
    await devnet_client.estimate_fee(invoke_est_fee_v3)


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
    assert_required_signer_of_bypass_call,
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

    await assert_required_signer_of_bypass_call(account,
                                                REQUIRED_SIGNER_STRONG,
                                                amount=int(1.0001 * 10**18))
    await assert_required_signer_of_bypass_call(account,
                                                REQUIRED_SIGNER_MULTISIG,
                                                amount=int(2.0001 * 10**18))

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
    await assert_required_signer_of_bypass_call(account,
                                                REQUIRED_SIGNER_STARK,
                                                amount=0)
    await assert_required_signer_of_bypass_call(account,
                                                REQUIRED_SIGNER_STRONG,
                                                amount=int(1.0001 * 10**18))
    await assert_required_signer_of_bypass_call(account,
                                                REQUIRED_SIGNER_MULTISIG,
                                                amount=int(2.0001 * 10**18))

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
    withdrawal_limit_low = ETHER
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
    ["multisig_threshold", "low_threshold", "high_threshold", "extra_signers"],
    [
        (0, 100 * USDC, None, []),
        (2, 100 * USDC, None, []),
        (2, 100 * USDC, 200 * USDC, []),
        (2, 100 * USDC, None, [SECP256R1_SIGNER_TYPE]),
        (2, 100 * USDC, 200 * USDC, [SECP256R1_SIGNER_TYPE]),
        (3, 100 * USDC, None, [SECP256R1_SIGNER_TYPE]),
        (3, 100 * USDC, 200 * USDC, [SECP256R1_SIGNER_TYPE]),
        (2, 100 * USDC, None, [WEBAUTHN_SIGNER_TYPE]),
        (2, 100 * USDC, 200 * USDC, [WEBAUTHN_SIGNER_TYPE]),
    ],
    ids=[
        "with_secp256r1_no_multisig_no_high",
        "with_secp256r1_multisig_no_high",
        "with_secp256r1_multisig_with_high",
        "with_secp256r1_multisig_no_high_2_of_3",
        "with_secp256r1_multisig_with_high_2_of_3",
        "with_secp256r1_multisig_no_high_3_of_3",
        "with_secp256r1_multisig_with_high_3_of_3",
        "with_secp256r1_and_webauthn_multisig_no_high_2_of_3",
        "with_secp256r1_and_webauthn_multisig_with_high_2_of_3",
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
    extra_signers,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    stark_privk = random.randint(1, 10**10)
    secp256r1_keypair = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])

    account, _ = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_threshold if multisig_threshold == 0 else 2,
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

        signers = [secp256r1_signer]
        if not WEBAUTHN_SIGNER_TYPE in extra_signers:
            signers.insert(0, stark_signer)
        await add_signers(extra_signers, multisig_threshold, account,
                          devnet_client, signers)
        account.signer = create_multisig_signers(signers)

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
