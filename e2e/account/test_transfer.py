from e2e.utils.utils import *
from e2e.utils.fixtures import *

import pytest
import requests
import random

from starknet_py.net.account.account import Account
from starknet_py.net.client_models import Call
from starknet_py.net.full_node_client import FullNodeClient
from starknet_py.hash.selector import get_selector_from_name
from starknet_py.net.client_errors import ClientError
from starknet_py.transaction_errors import (
    TransactionNotReceivedError,
    TransactionRevertedError,
)


@pytest.mark.asyncio
async def test_pricing_contract(
    init_starknet,
    account_deployer,
    init_pricing_contract,
):
    _ = init_starknet


@pytest.mark.parametrize(
    [
        "call_type",
        "lower_threshold",
        "high_threshold",
        "multisig_threshold",
        "bypass_signer",
        "bypass_token_name",
        "is_webauthn",
        "execute_v3",
    ],
    [
        ('transfer', 45 * USDC, 0, 2, 'hws', 'eth', True, False),
        ('transfer', 45 * USDC, 0, 2, 'stark', 'eth', True, False),
        ('transfer', 45 * USDC, 0, 0, 'stark', 'usdc', True, False),
        ('transfer', 45 * USDC, 0, 2, 'stark', 'usdc', True, False),
        ('transfer', 45 * USDC, 0, 2, 'hws', 'usdc', True, False),
        ('transfer', 0, 45 * USDC, 2, 'hws', 'usdc', True, False),
        ('transfer', 0, 45 * USDC, 2, 'hws', 'eth', True, False),
        ('transfer', 45 * USDC, 0, 0, 'stark', 'eth', True, False),
        ('transfer', 45 * USDC, 0, 2, 'stark', 'usdc', False, False),
        ('transfer', 45 * USDC, 0, 2, 'hws', 'usdc', False, False),
        ('transfer', 45 * USDC, 0, 0, 'stark', 'usdc', False, False),
        ('transfer', 0, 45 * USDC, 2, 'hws', 'usdc', False, False),
        ('transfer', 45 * USDC, 0, 2, 'stark', 'eth', False, False),
        ('transfer', 45 * USDC, 0, 2, 'hws', 'eth', False, False),
        ('transfer', 0, 45 * USDC, 2, 'hws', 'eth', False, False),
        ('transfer', 45 * USDC, 0, 0, 'stark', 'eth', False, False),
        ('transfer', 45 * USDC, 0, 2, 'hws', 'eth', True, True),
        ('transfer', 45 * USDC, 0, 2, 'stark', 'eth', True, True),
        ('transfer', 45 * USDC, 0, 0, 'stark', 'usdc', True, True),
        ('transfer', 45 * USDC, 0, 2, 'stark', 'usdc', True, True),
        ('transfer', 45 * USDC, 0, 2, 'hws', 'usdc', True, True),
        ('transfer', 0, 45 * USDC, 2, 'hws', 'usdc', True, True),
        ('transfer', 0, 45 * USDC, 2, 'hws', 'eth', True, True),
        ('transfer', 45 * USDC, 0, 0, 'stark', 'eth', True, True),
        ('transfer', 45 * USDC, 0, 2, 'stark', 'usdc', False, True),
        ('transfer', 45 * USDC, 0, 2, 'hws', 'usdc', False, True),
        ('transfer', 45 * USDC, 0, 0, 'stark', 'usdc', False, True),
        ('transfer', 0, 45 * USDC, 2, 'hws', 'usdc', False, True),
        ('transfer', 45 * USDC, 0, 2, 'stark', 'eth', False, True),
        ('transfer', 45 * USDC, 0, 2, 'hws', 'eth', False, True),
        ('transfer', 0, 45 * USDC, 2, 'hws', 'eth', False, True),
        ('transfer', 45 * USDC, 0, 0, 'stark', 'eth', False, True),
    ],
    ids=[
        "transfer_low_thresh_multisig_eth_with_hws_webauthn",
        "transfer_low_thresh_multisig_eth_with_stark_webauthn",
        "transfer_low_thresh_usdc_with_stark_webauthn",
        "transfer_low_thresh_multisig_usdc_with_stark_webauthn",
        "transfer_low_thresh_multisig_usdc_with_hws_webauthn",
        "transfer_high_thresh_multisig_usdc_with_hws_webauthn",
        "transfer_high_thresh_multisig_eth_with_hws_webauthn",
        "transfer_low_thresh_eth_with_hws_webauthn",
        "transfer_low_thresh_multisig_usdc_with_stark",
        "transfer_low_thresh_multisig_usdc_with_hws",
        "transfer_low_thresh_usdc_with_stark",
        "transfer_high_thresh_multisig_usdc_with_hws",
        "transfer_low_thresh_multisig_eth_with_stark",
        "transfer_low_thresh_multisig_eth_with_hws",
        "transfer_high_thresh_multisig_eth_with_hws",
        "transfer_low_thresh_eth_with_hws",
        "transfer_low_thresh_multisig_eth_with_hws_webauthn_v3",
        "transfer_low_thresh_multisig_eth_with_stark_webauthn_v3",
        "transfer_low_thresh_usdc_with_stark_webauthn_v3",
        "transfer_low_thresh_multisig_usdc_with_stark_webauthn_v3",
        "transfer_low_thresh_multisig_usdc_with_hws_webauthn_v3",
        "transfer_high_thresh_multisig_usdc_with_hws_webauthn_v3",
        "transfer_high_thresh_multisig_eth_with_hws_webauthn_v3",
        "transfer_low_thresh_eth_with_hws_webauthn_v3",
        "transfer_low_thresh_multisig_usdc_with_stark_v3",
        "transfer_low_thresh_multisig_usdc_with_hws_v3",
        "transfer_low_thresh_usdc_with_stark_v3",
        "transfer_high_thresh_multisig_usdc_with_hws_v3",
        "transfer_low_thresh_multisig_eth_with_stark_v3",
        "transfer_low_thresh_multisig_eth_with_hws_v3",
        "transfer_high_thresh_multisig_eth_with_hws_v3",
        "transfer_low_thresh_eth_with_hws_v3",
    ],
)
@pytest.mark.asyncio
async def test_successful_single_range_transfer(
    init_starknet,
    init_pricing_contract,
    account_deployer,
    mock_usdc_threshold_token,
    do_bypass,
    set_and_assert_high_threshold,
    get_fee_rate,
    get_daily_spend,
    clean_token_config,
    call_type,
    lower_threshold,
    high_threshold,
    multisig_threshold,
    bypass_signer,
    bypass_token_name,
    is_webauthn,
    execute_v3,
):
    token_address = ETH_TOKEN_ADDRESS if bypass_token_name == 'eth' else mock_usdc_threshold_token.address
    rate = 100 if bypass_token_name == 'eth' else 1
    fee_rate = 100
    fee_decimals_factor = 10**12  # usdc is 6 decimals, 18-6=12
    fee_rate_in_usdc_wei = fee_rate * USDC
    value_decimals_factor = 10**12 if bypass_token_name == 'eth' else 1

    max_fee = int(0.1 * 10**18)
    secp256r1_keypair = generate_secp256r1_keypair()

    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient

    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk)
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    secp256r1_signer = create_secp256r1_signer(
        secp256r1_keypair[0]) if not is_webauthn else create_webauthn_signer(
            secp256r1_keypair[0])
    account, _ = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_threshold,
        lower_threshold,
        is_webauthn=is_webauthn,
        eth_fee_rate=fee_rate_in_usdc_wei,
        stark_fee_rate=fee_rate_in_usdc_wei,
        erc20_address_to_transfer=mock_usdc_threshold_token.address,
        deploy_with_v3=execute_v3,
    )
    account: Account

    strong_signer = secp256r1_signer if multisig_threshold == 0 else create_multisig_signer(
        stark_signer, secp256r1_signer)

    account.signer = strong_signer

    if bypass_token_name == 'usdc':
        await clean_token_config(
            account, fake_usdc_address=mock_usdc_threshold_token.address)
    else:
        await clean_token_config(account)

    get_rate_result = await get_fee_rate(account)
    assert get_rate_result == (fee_rate_in_usdc_wei if lower_threshold > 0 else
                               0), "eth rate should exist right after ctor"

    bypass_signer = stark_signer if bypass_signer == 'stark' else secp256r1_signer

    if high_threshold > 0:
        account.signer = strong_signer
        await set_and_assert_high_threshold(high_threshold, account)

    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == 0, "daily threshold should be 0"

    # check that strong signer works and doesnt affect the daily spendenture
    account.signer = strong_signer
    transfer_call = Call(to_addr=token_address,
                         selector=get_selector_from_name(call_type),
                         calldata=[devnet_account.address, *to_uint256(1)])

    if execute_v3:
        exec_txn = await account.execute_v3(
            calls=transfer_call,
            l1_resource_bounds=ResourceBounds(
                max_amount=int(max_fee / (100 * 10**9)),
                max_price_per_unit=100 * 10**9 + 1,
            ),
        )
    else:
        exec_txn = await account.execute(
            calls=transfer_call,
            max_fee=max_fee,
        )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == 0, "no daily amount spent after strong signer"

    account.signer = bypass_signer
    await do_bypass(token_address, 0, account, bypass_signer, call_type,
                    execute_v3)

    get_rate_result = await get_fee_rate(account)
    assert get_rate_result == fee_rate_in_usdc_wei, "incorrect rate"

    fee_spending = max_fee * fee_rate // fee_decimals_factor + 1
    extra_value = 1 if bypass_token_name == "eth" else 0
    daily_spend_result = await get_daily_spend(account)
    # extra 1 for the fee, and extra 1 for the value (only for eth, because usdc is the threshold currency)
    assert daily_spend_result == fee_spending, "daily threshold should only account for the fee since we moved a zero amount"

    account.signer = bypass_signer
    amount_to_transfer = ETHER // 10 if bypass_token_name == 'eth' else 10 * 10**6
    await do_bypass(token_address, amount_to_transfer, account, bypass_signer,
                    call_type, execute_v3)

    get_rate_result = await get_fee_rate(account)
    assert get_rate_result == fee_rate_in_usdc_wei, "rate should exist"

    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == 2 * fee_spending + amount_to_transfer * rate // value_decimals_factor + extra_value, "wrong daily threshold"

    with pytest.raises(Exception):
        await do_bypass(token_address, amount_to_transfer, account,
                        bypass_signer, call_type, execute_v3)

    # check the the fee was added on top of the daily spending
    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == 3 * fee_spending + amount_to_transfer * rate // value_decimals_factor + extra_value, "wrong daily threshold"

    # check that strong signer works
    strong_signer = secp256r1_signer if multisig_threshold == 0 else create_multisig_signer(
        stark_signer, secp256r1_signer)
    account.signer = strong_signer

    transfer_call = Call(
        to_addr=token_address,
        selector=get_selector_from_name(call_type),
        calldata=[devnet_account.address, *to_uint256(7 * 10**17)])

    if execute_v3:
        exec_txn = await account.execute_v3(
            calls=transfer_call,
            l1_resource_bounds=ResourceBounds(
                max_amount=int(max_fee / (100 * 10**9)),
                max_price_per_unit=100 * 10**9 + 1,
            ),
        )
    else:
        exec_txn = await account.execute(
            calls=transfer_call,
            max_fee=max_fee,
        )

    await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == 3 * fee_spending + amount_to_transfer * rate // value_decimals_factor + extra_value, "wrong daily threshold"

    # 2 days later
    requests.post(f"{devnet_url}/increase_time",
                  json={"time": int(2 * 24 * 60 * 60)})

    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == 0, "daily threshold should be zero after the day passes"


@pytest.mark.parametrize(
    [
        "call_type", "lower_threshold", "high_threshold", "bypass_token_name",
        "execute_v3"
    ],
    [
        ('transfer', 35 * USDC, 65 * USDC, 'usdc', False),
        ('transfer', 35 * USDC, 65 * USDC, 'eth', False),
        ('transfer', 35 * USDC, 65 * USDC, 'usdc', True),
        ('transfer', 35 * USDC, 65 * USDC, 'eth', True),
    ],
    ids=[
        "transfer_usdc",
        "transfer_eth",
        "transfer_usdc_v3",
        "transfer_eth_v3",
    ],
)
@pytest.mark.asyncio
async def test_successful_dual_threshold_transfer(
    init_starknet,
    account_deployer,
    init_pricing_contract,
    mock_usdc_threshold_token,
    do_bypass,
    set_and_assert_high_threshold,
    clean_token_config,
    get_fee_rate,
    get_daily_spend,
    call_type,
    lower_threshold,
    high_threshold,
    bypass_token_name,
    execute_v3,
):
    token_address = ETH_TOKEN_ADDRESS if bypass_token_name == 'eth' else mock_usdc_threshold_token.address
    rate = 100 if bypass_token_name == 'eth' else 1
    fee_rate = 100
    fee_decimals_factor = 10**12  # usdc is 6 decimals, 18-6=12
    fee_rate_in_wei = fee_rate * ETHER // fee_decimals_factor
    value_decimals_factor = 10**12 if bypass_token_name == 'eth' else 1
    max_fee = int(0.1 * 10**18)

    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient

    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk)
    secp256r1_keypair = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    secp256r1_signer = create_secp256r1_signer(secp256r1_keypair[0])
    multisig_threshold = 2

    account, _ = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_threshold,
        lower_threshold,
        erc20_address_to_transfer=mock_usdc_threshold_token.address,
        eth_fee_rate=fee_rate_in_wei,
        stark_fee_rate=fee_rate_in_wei,
        deploy_with_v3=execute_v3,
    )
    account: Account

    multisig_signer = create_multisig_signer(stark_signer, secp256r1_signer)
    account.signer = multisig_signer
    if bypass_token_name == 'usdc':
        await clean_token_config(
            account, fake_usdc_address=mock_usdc_threshold_token.address)
    else:
        await clean_token_config(account)

    get_rate_result = await get_fee_rate(account)
    assert get_rate_result == fee_rate_in_wei, "eth rate should exist right after ctor"

    account.signer = multisig_signer
    await set_and_assert_high_threshold(high_threshold, account)

    bypass_signer = stark_signer
    amount_to_transfer = ETHER // 10 if bypass_token_name == 'eth' else 10 * 10**6

    await do_bypass(token_address, amount_to_transfer, account, bypass_signer,
                    call_type, execute_v3)
    extra_value = 1 if bypass_token_name == "eth" else 0
    fee_spending = max_fee * fee_rate // fee_decimals_factor + 1

    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == fee_spending + amount_to_transfer * rate // value_decimals_factor + extra_value, "wrong daily spend"

    with pytest.raises(Exception):
        await do_bypass(token_address, amount_to_transfer, account,
                        bypass_signer, call_type, execute_v3)

    # now trying with the stronger signer
    bypass_signer = secp256r1_signer
    await do_bypass(token_address, amount_to_transfer, account, bypass_signer,
                    call_type, execute_v3)

    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == 3 * fee_spending + 2 * amount_to_transfer * rate // value_decimals_factor + 2 * extra_value, "wrong daily spend"

    with pytest.raises(Exception):
        await do_bypass(token_address, amount_to_transfer, account,
                        bypass_signer, call_type, execute_v3)

    daily_spend_result = await get_daily_spend(account)

    # check that strong signer works
    account.signer = multisig_signer
    transfer_call = Call(
        to_addr=token_address,
        selector=get_selector_from_name(call_type),
        calldata=[devnet_account.address, *to_uint256(amount_to_transfer)])

    if execute_v3:
        exec_txn = await account.execute_v3(
            calls=transfer_call,
            l1_resource_bounds=ResourceBounds(
                max_amount=int(max_fee / (100 * 10**9)),
                max_price_per_unit=100 * 10**9 + 1,
            ),
        )
    else:
        exec_txn = await account.execute(
            calls=transfer_call,
            max_fee=max_fee,
        )

    await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == 4 * fee_spending + 2 * amount_to_transfer * rate // value_decimals_factor + 2 * extra_value, "wrong dialy spend"

    # 2 days later
    requests.post(f"{devnet_url}/increase_time",
                  json={"time": int(2 * 24 * 60 * 60)})

    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == 0, "daily threshold should be zero after the day passes"


@pytest.mark.parametrize(
    ["call_type"],
    [
        ('transfer', ),
    ],
    ids=[
        "transfer",
    ],
)
@pytest.mark.asyncio
async def test_non_whitelisted_token_cannot_bypass(
    init_starknet,
    account_deployer,
    init_pricing_contract,
    pepe_token,
    do_bypass,
    call_type,
):
    lower_threshold = 100 * 10**18
    max_fee = 0.1 * 10**18
    rate = 100
    rate_in_wei = rate * ETHER

    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient

    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk)
    secp256r1_keypair = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    multisig_threshold = 0

    account, _ = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_threshold,
        lower_threshold,
        eth_fee_rate=rate_in_wei,
        stark_fee_rate=rate_in_wei,
    )
    account: Account

    with pytest.raises(ClientError, match=encode_string_as_hex('INVALID_SIG')):
        await do_bypass(pepe_token.address, 7 * 10**17, account, stark_signer,
                        call_type)


@pytest.mark.asyncio
async def test_bad_calls_structure_cant_bypass(
    init_starknet,
    init_pricing_contract,
    account_deployer,
    do_bypass,
):
    lower_threshold = 100 * 10**18
    max_fee = 0.1 * 10**18
    rate = 100
    rate_in_wei = rate * ETHER

    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient

    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk)
    secp256r1_keypair = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    multisig_threshold = 2

    account, _ = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_threshold,
        lower_threshold,
        eth_fee_rate=rate_in_wei,
        stark_fee_rate=rate_in_wei,
    )
    account: Account

    with pytest.raises(ClientError, match=encode_string_as_hex('INVALID_SIG')):
        account.signer = stark_signer

        non_bypass_call = Call(
            to_addr=0,
            selector=get_selector_from_name("get_total_number_of_pools"),
            calldata=[])

        exec_txn = await account.execute(
            calls=[non_bypass_call],
            max_fee=int(0.1 * 10**18),
        )

        await devnet_client.wait_for_tx(exec_txn.transaction_hash)


@pytest.mark.asyncio
async def test_bad_transfer_call(
    init_starknet,
    account_deployer,
    do_bypass,
):
    lower_threshold = 100 * 10**18
    max_fee = 0.1 * 10**18
    rate = 100
    rate_in_wei = rate * ETHER

    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient

    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk)
    secp256r1_keypair = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    multisig_threshold = 2

    account, _ = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_threshold,
        lower_threshold,
        eth_fee_rate=rate_in_wei,
        stark_fee_rate=rate_in_wei,
    )
    account: Account
    account.signer = stark_signer
    with pytest.raises(ClientError, match=encode_string_as_hex('INVALID_SIG')):

        # transfer has 3 felt input but here i'm passing just 2
        malfunctioned_transfer_call = Call(
            to_addr=ETH_TOKEN_ADDRESS,
            selector=get_selector_from_name("transfer"),
            calldata=[0, 10**17])

        exec_txn = await account.execute(
            calls=[malfunctioned_transfer_call],
            max_fee=int(0.1 * 10**18),
        )

        await devnet_client.wait_for_tx(exec_txn.transaction_hash)


@pytest.mark.parametrize(
    [
        "call_type",
        "fee_rate_input",
    ],
    [
        ('transfer', 50),
        ('transfer', 150),
        ('transfer', 98),
        ('transfer', 102),
    ],
    ids=[
        "transfer_lower_rate",
        "transfer_higher_rate",
        "transfer_lower_close_rate",
        "transfer_higher_close_rate",
    ],
)
@pytest.mark.asyncio
async def test_changing_rate_works(
    init_starknet,
    account_deployer,
    init_pricing_contract,
    clean_token_config,
    get_fee_rate,
    get_daily_spend,
    do_bypass,
    call_type,
    fee_rate_input,
):
    max_fee = 10**17
    fee_rate_input_in_wei = fee_rate_input * USDC

    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient

    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk)
    secp256r1_keypair = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    multisig_threshold = 0

    account, _ = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_threshold,
        100 * USDC,
        eth_fee_rate=fee_rate_input_in_wei,
        stark_fee_rate=100 * fee_rate_input_in_wei,
    )
    account: Account
    secp256r1_signer = create_secp256r1_signer(secp256r1_keypair[0])
    account.signer = secp256r1_signer
    await clean_token_config(account)
    current_fee_rate = await get_fee_rate(account)
    assert current_fee_rate == fee_rate_input_in_wei, 'fee rate should be the original one given in ctor'

    current_fee_rate_stark = await get_fee_rate(account, token_name="stark")
    amount_to_transfer = 10**17
    await do_bypass(ETH_TOKEN_ADDRESS, amount_to_transfer, account,
                    stark_signer, call_type)

    actual_fee_rate = 100
    actual_fee_rate_in_wei = actual_fee_rate * USDC
    current_fee_rate = await get_fee_rate(account)
    if abs(actual_fee_rate_in_wei -
           fee_rate_input_in_wei) < fee_rate_input_in_wei * 0.05:
        assert current_fee_rate == fee_rate_input_in_wei, 'wrong fee rate'
    else:
        assert current_fee_rate == actual_fee_rate_in_wei, 'wrong fee rate'

    daily_spend = await get_daily_spend(account)
    assert daily_spend == max_fee * actual_fee_rate // 10**12 + amount_to_transfer * actual_fee_rate // 10**12 + 2, 'daily spending should be based on updated rate regardless of rate storage changes'
    current_fee_rate_stark = await get_fee_rate(account, token_name="stark")
    assert current_fee_rate_stark == 100 * fee_rate_input_in_wei, 'stark fee should not have changed'


@pytest.mark.asyncio
async def test_transfer_amount_too_large_for_u128(
    init_starknet,
    init_pricing_contract,
    account_deployer,
    clean_token_config,
    do_bypass,
):
    lower_threshold = 100 * 10**18
    max_fee = 10**17
    fee_rate_input_in_wei = 100 * ETHER

    _, _, _ = init_starknet

    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk)
    secp256r1_keypair = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    multisig_threshold = 0

    account, _ = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_threshold,
        lower_threshold,
        eth_fee_rate=fee_rate_input_in_wei,
        stark_fee_rate=fee_rate_input_in_wei,
    )
    account: Account
    secp256r1_signer = create_secp256r1_signer(secp256r1_keypair[0])
    account.signer = secp256r1_signer
    await clean_token_config(account)

    amount_to_transfer = 2**129
    with pytest.raises(TransactionRevertedError):
        await do_bypass(ETH_TOKEN_ADDRESS, amount_to_transfer, account,
                        stark_signer, "transfer")


@pytest.mark.parametrize(
    [
        "lower_threshold",
        "high_threshold",
        "multisig_threshold",
        "bypass_signer",
        "execute_v3",
    ],
    [
        (55 * USDC, 0, 2, 'stark', False),
        (55 * USDC, 0, 2, 'hws', False),
        (55 * USDC, 0, 0, 'stark', False),
        (0, 55 * USDC, 2, 'hws', False),
        (15 * USDC, 55 * USDC, 2, 'hws', False),
        (55 * USDC, 0, 2, 'stark', True),
        (55 * USDC, 0, 2, 'hws', True),
        (55 * USDC, 0, 0, 'stark', True),
        (0, 55 * USDC, 2, 'hws', True),
        (15 * USDC, 55 * USDC, 2, 'hws', True),
    ],
    ids=[
        "low_thresh_multisig_with_stark",
        "low_thresh_multisig_with_hws",
        "low_thresh_no_multsig_with_stark",
        "high_thresh_multisig_with_hws",
        "low_high_thresh_multisig_with_hws",
        "low_thresh_multisig_with_stark_v3",
        "low_thresh_multisig_with_hws_v3",
        "low_thresh_no_multsig_with_stark_v3",
        "high_thresh_multisig_with_hws_v3",
        "low_high_thresh_multisig_with_hws_v3",
    ],
)
@pytest.mark.asyncio
async def test_successful_multicall(
        init_starknet, account_deployer, init_pricing_contract,
        mock_usdc_threshold_token, do_single_bypass_multicall,
        do_double_bypass_multicall, set_and_assert_high_threshold,
        clean_token_config, get_fee_rate, get_daily_spend, lower_threshold,
        high_threshold, multisig_threshold, bypass_signer, execute_v3):
    rate_in_wei = 100 * USDC
    max_fee = int(0.1 * 10**18)
    secp256r1_keypair = generate_secp256r1_keypair()

    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient

    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk)
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    secp256r1_signer = create_secp256r1_signer(secp256r1_keypair[0])
    multisig_signer = create_multisig_signer(stark_signer, secp256r1_signer)
    strong_signer = multisig_signer if multisig_threshold == 2 else secp256r1_signer

    account, _ = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_threshold,
        lower_threshold,
        eth_fee_rate=rate_in_wei,
        stark_fee_rate=rate_in_wei,
        erc20_address_to_transfer=mock_usdc_threshold_token.address,
        deploy_with_v3=execute_v3)
    account: Account

    account.signer = strong_signer
    await clean_token_config(
        account,
        fake_usdc_address=mock_usdc_threshold_token.address,
        add_custom_call_double=False)

    bypass_signer = stark_signer if bypass_signer == 'stark' else secp256r1_signer

    if high_threshold > 0:
        account.signer = secp256r1_signer if multisig_threshold == 0 else create_multisig_signer(
            stark_signer, secp256r1_signer)
        await set_and_assert_high_threshold(high_threshold, account)

    get_rate_result = await get_fee_rate(account)
    assert get_rate_result == rate_in_wei, "eth rate should exist right after ctor"

    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == 0, "daily threshold should be 0"

    # check that strong signer works and doesnt affect the daily spendenture
    strong_signer = secp256r1_signer if multisig_threshold == 0 else multisig_signer

    account.signer = strong_signer
    transfer_call = Call(to_addr=ETH_TOKEN_ADDRESS,
                         selector=get_selector_from_name("transfer"),
                         calldata=[devnet_account.address, *to_uint256(1)])

    exec_txn = await account.execute(
        calls=transfer_call,
        max_fee=max_fee,
    )

    await devnet_client.wait_for_tx(exec_txn.transaction_hash)
    daily_spend_result = await get_daily_spend(account)
    assert daily_spend_result == 0, "no daily amount spent after strong signer"

    await do_single_bypass_multicall(100, ETH_TOKEN_ADDRESS, account,
                                     bypass_signer, execute_v3)

    get_rate_result = await get_fee_rate(account)
    assert get_rate_result == rate_in_wei, "rate should exist"

    expected_fee_spending = max_fee * rate_in_wei // (ETHER) + 1
    daily_spend_result = await get_daily_spend(account)
    assert abs(daily_spend_result -
               (expected_fee_spending + 1)) <= 10, "wrong daily threshold"

    await clean_token_config(
        account,
        fake_usdc_address=mock_usdc_threshold_token.address,
        add_custom_call_double=True)

    await do_double_bypass_multicall(100, ETH_TOKEN_ADDRESS, 100,
                                     mock_usdc_threshold_token.address,
                                     account, bypass_signer, execute_v3)

    get_rate_result = await get_fee_rate(account)
    assert get_rate_result == rate_in_wei, "rate should exist"

    expected_fee_spending += max_fee * rate_in_wei // (ETHER) + 1
    daily_spend_result = await get_daily_spend(account)
    assert abs(daily_spend_result -
               (expected_fee_spending + 1)) <= 10, "wrong daily threshold"


@pytest.mark.asyncio
async def test_multicall_bypass_failures(
    init_starknet,
    account_deployer,
    init_pricing_contract,
    mock_usdc_threshold_token,
    do_single_bypass_multicall,
    do_double_bypass_multicall,
    set_and_assert_high_threshold,
    clean_token_config,
    get_fee_rate,
    get_daily_spend,
):
    pricing_contract_address, _, _ = init_pricing_contract
    rate_in_wei = 100 * USDC
    max_fee = int(0.1 * 10**18)
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient

    stark_privk = random.randint(1, 10**10)
    stark_signer = create_stark_signer(stark_privk)
    secp256r1_keypair = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_keypair[1])
    secp256r1_signer = create_secp256r1_signer(secp256r1_keypair[0])
    lower_threshold = 500 * USDC

    account, _ = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        0,
        lower_threshold,
        eth_fee_rate=rate_in_wei,
        stark_fee_rate=rate_in_wei,
        erc20_address_to_transfer=mock_usdc_threshold_token.address)
    account: Account
    bypass_signer = stark_signer

    # approves must be to the white listed call address - single approve
    account.signer = secp256r1_signer
    await clean_token_config(
        account,
        fake_usdc_address=mock_usdc_threshold_token.address,
        add_custom_call_double=False)
    bad_approve_bypass_call = Call(to_addr=ETH_TOKEN_ADDRESS,
                                   selector=get_selector_from_name("approve"),
                                   calldata=[101010, *to_uint256(100)])
    custom_call = Call(to_addr=pricing_contract_address,
                       selector=get_selector_from_name("get_average_price"),
                       calldata=[0, 0])

    account.signer = stark_signer
    with pytest.raises(ClientError, match=encode_string_as_hex("INVALID_SIG")):
        exec_txn = await account.execute(
            calls=[
                bad_approve_bypass_call,
                custom_call,
            ],
            max_fee=int(0.1 * 10**18),
        )
        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    # approves must be to the white listed call address - double approve
    account.signer = secp256r1_signer
    await clean_token_config(
        account,
        fake_usdc_address=mock_usdc_threshold_token.address,
        add_custom_call_double=True)
    good_approve_bypass_call = Call(
        to_addr=ETH_TOKEN_ADDRESS,
        selector=get_selector_from_name("approve"),
        calldata=[pricing_contract_address, *to_uint256(100)])
    bad_second_approve_bypass_call = Call(
        to_addr=mock_usdc_threshold_token.address,
        selector=get_selector_from_name("approve"),
        calldata=[10100101, *to_uint256(100)])
    custom_call = Call(to_addr=pricing_contract_address,
                       selector=get_selector_from_name("get_average_price"),
                       calldata=[0, 0])

    account.signer = stark_signer
    with pytest.raises(ClientError, match=encode_string_as_hex("INVALID_SIG")):
        exec_txn = await account.execute(
            calls=[
                good_approve_bypass_call,
                bad_approve_bypass_call,
                custom_call,
            ],
            max_fee=int(0.1 * 10**18),
        )
        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    # can't send the same approve twice
    account.signer = secp256r1_signer
    await clean_token_config(
        account,
        fake_usdc_address=mock_usdc_threshold_token.address,
        add_custom_call_double=True)
    approve_bypass_call1 = Call(
        to_addr=ETH_TOKEN_ADDRESS,
        selector=get_selector_from_name("approve"),
        calldata=[pricing_contract_address, *to_uint256(100)])
    approve_bypass_call2 = Call(
        to_addr=ETH_TOKEN_ADDRESS,
        selector=get_selector_from_name("approve"),
        calldata=[pricing_contract_address, *to_uint256(100)])
    custom_call = Call(to_addr=pricing_contract_address,
                       selector=get_selector_from_name("get_average_price"),
                       calldata=[0, 0])

    account.signer = stark_signer
    with pytest.raises(ClientError, match=encode_string_as_hex("INVALID_SIG")):
        exec_txn = await account.execute(
            calls=[
                approve_bypass_call1,
                approve_bypass_call2,
                custom_call,
            ],
            max_fee=int(0.1 * 10**18),
        )
        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    # can't send double white listed call when single is whitlisted
    account.signer = secp256r1_signer
    await clean_token_config(
        account,
        fake_usdc_address=mock_usdc_threshold_token.address,
        add_custom_call_double=False)
    approve_bypass_call1 = Call(
        to_addr=ETH_TOKEN_ADDRESS,
        selector=get_selector_from_name("approve"),
        calldata=[pricing_contract_address, *to_uint256(100)])
    approve_bypass_call2 = Call(
        to_addr=ETH_TOKEN_ADDRESS,
        selector=get_selector_from_name("approve"),
        calldata=[pricing_contract_address, *to_uint256(100)])
    custom_call = Call(to_addr=pricing_contract_address,
                       selector=get_selector_from_name("get_average_price"),
                       calldata=[0, 0])

    account.signer = stark_signer
    with pytest.raises(ClientError, match=encode_string_as_hex("INVALID_SIG")):
        exec_txn = await account.execute(
            calls=[
                approve_bypass_call1,
                approve_bypass_call2,
                custom_call,
            ],
            max_fee=int(0.1 * 10**18),
        )
        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    # can't send single white listed call when double is whitlisted
    account.signer = secp256r1_signer
    await clean_token_config(
        account,
        fake_usdc_address=mock_usdc_threshold_token.address,
        add_custom_call_double=True)
    good_approve_bypass_call = Call(
        to_addr=ETH_TOKEN_ADDRESS,
        selector=get_selector_from_name("approve"),
        calldata=[pricing_contract_address, *to_uint256(100)])

    custom_call = Call(to_addr=pricing_contract_address,
                       selector=get_selector_from_name("get_average_price"),
                       calldata=[0, 0])

    account.signer = stark_signer
    with pytest.raises(ClientError, match=encode_string_as_hex("INVALID_SIG")):
        exec_txn = await account.execute(
            calls=[
                good_approve_bypass_call,
                custom_call,
            ],
            max_fee=int(0.1 * 10**18),
        )
        await devnet_client.wait_for_tx(exec_txn.transaction_hash)
