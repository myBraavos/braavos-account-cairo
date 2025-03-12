from e2e.utils.utils import *
from e2e.utils.fixtures import *

from collections import namedtuple
import pytest
import random

from poseidon_py.poseidon_hash import poseidon_hash_many
from starknet_py.constants import DEFAULT_DEPLOYER_ADDRESS, FEE_CONTRACT_ADDRESS
from starknet_py.net.account.account import AccountTransaction, Account
from starknet_py.net.client_models import Call
from starknet_py.net.full_node_client import FullNodeClient, _create_broadcasted_txn
from starknet_py.hash.address import compute_address
from starknet_py.hash.selector import get_selector_from_name
from starknet_py.hash.utils import message_signature, private_to_stark_key
from starknet_py.net.models.chains import StarknetChainId


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "secp256r1_keypair",
        "is_webauthn",
        "multisig_threshold",
        "withdrawal_limit_low",
        "fee_rate",
        "deploy_with_v3",
    ],
    [
        (None, False, 0, 0, 0, False),
        (generate_secp256r1_keypair(), False, 0, 0, 0, False),
        (generate_secp256r1_keypair(), False, 2, 0, 0, False),
        (generate_secp256r1_keypair(), True, 0, 0, 0, False),
        (generate_secp256r1_keypair(), True, 2, 0, 0, False),
        (generate_secp256r1_keypair(), False, 0, 50 * USDC, 100 * USDC, False),
        (generate_secp256r1_keypair(), False, 2, 50 * USDC, 100 * USDC, False),
        (generate_secp256r1_keypair(), True, 0, 50 * USDC, 100 * USDC, False),
        (generate_secp256r1_keypair(), True, 2, 50 * USDC, 100 * USDC, False),
        (None, False, 0, 0, 0, True),
        (generate_secp256r1_keypair(), False, 0, 0, 0, True),
        (generate_secp256r1_keypair(), False, 2, 0, 0, True),
        (generate_secp256r1_keypair(), True, 0, 0, 0, True),
        (generate_secp256r1_keypair(), True, 2, 0, 0, True),
        (generate_secp256r1_keypair(), False, 0, 50 * USDC, 100 * USDC, True),
        (generate_secp256r1_keypair(), False, 2, 50 * USDC, 100 * USDC, True),
        (generate_secp256r1_keypair(), True, 0, 50 * USDC, 100 * USDC, True),
        (generate_secp256r1_keypair(), True, 2, 50 * USDC, 100 * USDC, True),
    ],
    ids=[
        "basic_stark_signer",
        "with_secp256r1_no_multisig",
        "with_secp256r1_multisig",
        "with_webauthn_no_multisig",
        "with_webauthn_multisig",
        "with_secp256r1_no_multisig_with_thresh",
        "with_secp256r1_multisig_with_thresh",
        "with_webauthn_secp256r1_no_multisig_with_thresh",
        "with_webauthn_secp256r1_multisig_with_thresh",
        "basic_stark_signer_v3_deployment",
        "with_secp256r1_no_multisig_v3_deployment",
        "with_secp256r1_multisig_v3_deployment",
        "with_webauthn_no_multisig_v3_deployment",
        "with_webauthn_multisig_v3_deployment",
        "with_secp256r1_no_multisig_with_thresh_v3_deployment",
        "with_secp256r1_multisig_with_thresh_v3_deployment",
        "with_webauthn_secp256r1_no_multisig_with_thresh_v3_deployment",
        "with_webauthn_secp256r1_multisig_with_thresh_v3_deployment",
    ],
)
async def test_deployment(
    init_starknet,
    account_declare,
    init_pricing_contract,
    clean_token_config,
    account_deployer,
    assert_required_signer,
    assert_required_signer_of_bypass_call,
    secp256r1_keypair,
    is_webauthn,
    multisig_threshold,
    withdrawal_limit_low,
    fee_rate,
    deploy_with_v3,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    account_chash, _, _, _ = account_declare
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    stark_pubk = private_to_stark_key(stark_privk)
    secp256r1_pubk = None if secp256r1_keypair is None else flatten_seq(
        secp256r1_keypair[1])

    account, deploy_txn_hash = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_threshold,
        withdrawal_limit_low=withdrawal_limit_low,
        eth_fee_rate=fee_rate,
        stark_fee_rate=fee_rate,
        is_webauthn=is_webauthn,
        deploy_with_v3=deploy_with_v3)
    account: Account
    actual_chash = await devnet_client.get_class_hash_at(account.address)
    assert actual_chash == account_chash
    legacy_stark_signer = create_legacy_stark_signer(stark_privk)
    stark_signer = create_stark_signer(stark_privk)
    balanceof_call = Call(
        to_addr=int(FEE_CONTRACT_ADDRESS, 16),
        selector=get_selector_from_name('balanceOf'),
        calldata=[account.address],
    )
    deploy_txn_receipt = await devnet_client.get_transaction_receipt(
        deploy_txn_hash)
    assert txn_receipt_contains_event(
        deploy_txn_receipt,
        [get_selector_from_name("OwnerAdded"), stark_pubk],
        [STARK_SIGNER_TYPE],
    ) is True, "no stark added event emitted"

    if withdrawal_limit_low != 0:
        assert txn_receipt_contains_event(
            deploy_txn_receipt,
            [get_selector_from_name("WithdrawalLimitLowSet")],
            [withdrawal_limit_low],
            True,
        ) is True, "no withdrawal limit set"

    if secp256r1_keypair is None:
        # make sure stark signer can sign
        account.signer = stark_signer
        await execute_calls(account, balanceof_call)
        await execute_calls(account, balanceof_call, execute_v3=True)

        # make sure legacy stark signer can sign
        account.signer = legacy_stark_signer
        await execute_calls(account, balanceof_call)
        await execute_calls(account, balanceof_call, execute_v3=True)
        await assert_required_signer(account, balanceof_call,
                                     REQUIRED_SIGNER_STARK)
    else:
        if secp256r1_keypair is not None:
            assert txn_receipt_contains_event(
                deploy_txn_receipt,
                [
                    get_selector_from_name("OwnerAdded"),
                    poseidon_hash_many(secp256r1_pubk),
                ],
                [
                    WEBAUTHN_SIGNER_TYPE
                    if is_webauthn else SECP256R1_SIGNER_TYPE
                ],
            ) is True, "no secp256r1 signer added event emitted"

        # make sure stark signer can't sign
        await assert_execute_fails_with_signer(
            account,
            balanceof_call,
            stark_signer,
            'INVALID_SIG',
        )

        await assert_execute_fails_with_signer(
            account,
            balanceof_call,
            legacy_stark_signer,
            'INVALID_SIG',
        )

        strong_signer = create_webauthn_signer(
            secp256r1_keypair[0]) if is_webauthn else create_secp256r1_signer(
                secp256r1_keypair[0])
        await is_account_signer(
            account, poseidon_hash_many(flatten_seq(secp256r1_keypair[1])))
        if multisig_threshold == 0:
            account.signer = strong_signer
            await execute_calls(account, balanceof_call)
            await execute_calls(account, balanceof_call, execute_v3=True)
            await assert_required_signer(account, balanceof_call,
                                         REQUIRED_SIGNER_STRONG)
        elif multisig_threshold == 2:
            # assert a single strong signer isn't enough when multisig is set
            await assert_execute_fails_with_signer(
                account,
                balanceof_call,
                strong_signer,
                'INVALID_SIG',
            )

            account.signer = create_multisig_signer(stark_signer,
                                                    strong_signer)
            await execute_calls(account, balanceof_call)
            await execute_calls(account, balanceof_call, execute_v3=True)
            await assert_required_signer(account, balanceof_call,
                                         REQUIRED_SIGNER_MULTISIG)

        if withdrawal_limit_low > 0:
            await clean_token_config(account)
            await assert_required_signer_of_bypass_call(account,
                                                        REQUIRED_SIGNER_STARK,
                                                        amount=0)


@pytest.mark.asyncio
async def test_deployment_from_UDC(init_starknet, account_declare,
                                   account_contracts_str):
    devnet_url, devnet_client, devnet_account = init_starknet
    account_chash, base_account_chash, _, _ = account_declare
    base_account_sierra_str, _, _, _ = account_contracts_str

    devnet_account: Account
    devnet_client: FullNodeClient
    account_chash, _, _, _ = account_declare

    stark_privk = random.randint(1, 10**10)
    stark_pubk = private_to_stark_key(stark_privk)
    deployment_call = Call(
        to_addr=int(DEFAULT_DEPLOYER_ADDRESS, 16),
        selector=get_selector_from_name("deployContract"),
        calldata=[base_account_chash, stark_pubk, 0, 1, stark_pubk])
    expected_address = compute_address(class_hash=base_account_chash,
                                       salt=stark_pubk,
                                       constructor_calldata=[stark_pubk],
                                       deployer_address=0)

    secp256r1_kp = generate_secp256r1_keypair()
    secp256r1_pubk = flatten_seq(secp256r1_kp[1])

    def udc_depl_signer(txn: AccountTransaction):
        stark_sig = message_signature(txn.calculate_hash(DEVNET_CHAIN_ID),
                                      stark_privk)
        aux_data = [
            account_chash,
            *[2, *secp256r1_pubk],  # Dummy SECP256R1 signer
            0,  # Multisig
            0,  # DWL low
            0,  # Eth fee rate
            0,  # STRK fee rate
            DEVNET_CHAIN_ID,
        ]
        aux_hash = poseidon_hash_many(aux_data)
        aux_sig = message_signature(aux_hash, stark_privk)

        return [
            *stark_sig,
            *aux_data,
            *aux_sig,
        ]

    udc_deploy_signer = namedtuple(
        "UDCDeplSigner",
        ["sign_transaction"])(lambda depl_txn: udc_depl_signer(depl_txn))
    devnet_account_orig_signer = devnet_account.signer
    devnet_account.signer = udc_deploy_signer
    invoke_txn = await devnet_account.sign_invoke_v1(deployment_call,
                                                     max_fee=int(0.1 * 10**18))

    # starknet.py == 0.18.3 doesn't support latest simulate response, so call it raw
    # simul_res = await devnet_client.simulate_transactions([invoke_txn], skip_validate=True)
    res = await devnet_client._client.call(
        method_name="simulateTransactions",
        params={
            "block_id": "pending",
            "simulation_flags": ["SKIP_VALIDATE"],
            "transactions": [_create_broadcasted_txn(transaction=invoke_txn)],
        },
    )
    txn_state_diff = res[0]["transaction_trace"]["state_diff"]
    assert txn_state_diff["deployed_contracts"][0]["address"] == hex(
        expected_address), "NOT DEPLOYED"
    assert poseidon_hash_many(secp256r1_pubk) in [
        int(x["value"], 16) for store_diff in txn_state_diff["storage_diffs"]
        for x in store_diff["storage_entries"]
    ]
    devnet_account.signer = devnet_account_orig_signer


@pytest.mark.parametrize("is_v3", [True, False])
@pytest.mark.parametrize([
    "secp256r1_keypair",
    "is_webauthn",
    "multisig_threshold",
    "withdrawal_limit_low",
    "fee_rate",
], [
    (None, False, 0, 0, 0),
    (generate_secp256r1_keypair(), False, 2, 0, 0),
    (generate_secp256r1_keypair(), True, 2, 0, 0),
    (generate_secp256r1_keypair(), False, 0, 0, 0),
    (generate_secp256r1_keypair(), True, 0, 0, 0),
    (generate_secp256r1_keypair(), False, 0, 50 * USDC, 100 * USDC),
    (generate_secp256r1_keypair(), True, 0, 50 * USDC, 100 * USDC),
    (generate_secp256r1_keypair(), False, 2, 50 * USDC, 100 * USDC),
    (generate_secp256r1_keypair(), True, 2, 50 * USDC, 100 * USDC),
])
@pytest.mark.asyncio
async def test_deployment_from_factory(
        init_starknet, account_declare, declare_deploy_v1,
        account_contracts_str, init_account_factory, is_v3, secp256r1_keypair,
        is_webauthn, multisig_threshold, withdrawal_limit_low, fee_rate):
    devnet_url, devnet_client, devnet_account = init_starknet
    account_factory_address, _ = init_account_factory
    account_chash, base_account_chash, _, _ = account_declare
    base_account_sierra_str, _, _, _ = account_contracts_str
    devnet_account: Account
    devnet_client: FullNodeClient

    stark_privk = random.randint(1, 10**10)
    stark_pubk = private_to_stark_key(stark_privk)
    stark_signer = create_stark_signer(stark_privk)
    strong_signer_type = WEBAUTHN_SIGNER_TYPE if is_webauthn else SECP256R1_SIGNER_TYPE

    strong_signer_field = [0, 0, 0, 0, 0] if secp256r1_keypair is None else [
        strong_signer_type, *flatten_seq(secp256r1_keypair[1])
    ]
    aux_data = [
        account_chash,
        *strong_signer_field,
        multisig_threshold,
        withdrawal_limit_low,
        fee_rate,
        fee_rate,
        DEVNET_CHAIN_ID,
    ]
    aux_hash = poseidon_hash_many(aux_data)
    aux_sig = message_signature(aux_hash, stark_privk)

    additional_depl_data = [*aux_data, *aux_sig]

    deployment_call = Call(
        to_addr=account_factory_address,
        selector=get_selector_from_name("deploy_braavos_account"),
        calldata=[
            stark_pubk,
            len(additional_depl_data), *additional_depl_data
        ])
    expected_address = compute_address(class_hash=base_account_chash,
                                       salt=stark_pubk,
                                       constructor_calldata=[stark_pubk],
                                       deployer_address=0)
    exec_txn = await devnet_account.execute_v1(
        calls=deployment_call,
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    exec = await devnet_account.execute_v1(
        Call(
            to_addr=utils_v2.STRK_ADDRESS if is_v3 else ETH_TOKEN_ADDRESS,
            selector=get_selector_from_name("transfer"),
            calldata=[
                expected_address,
                105 * 10**18,
                0,
            ],
        ),
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec.transaction_hash)

    deployed_account = Account(
        client=devnet_client,
        address=expected_address,
        key_pair=KeyPair.from_private_key(stark_privk),
        chain=DEVNET_CHAIN_ID,
    )

    deployed_account_chash = await devnet_client.get_class_hash_at(
        deployed_account.address)
    assert deployed_account_chash == account_chash, "wrong account chash between ctor and init"
    balanceof_call = Call(
        to_addr=int(FEE_CONTRACT_ADDRESS, 16),
        selector=get_selector_from_name('balanceOf'),
        calldata=[deployed_account.address],
    )

    secp_signer = None if secp256r1_keypair is None else (
        create_webauthn_signer(secp256r1_keypair[0])
        if is_webauthn else create_secp256r1_signer(secp256r1_keypair[0]))
    account_signer = deployed_account.signer if secp_signer is None else (
        secp_signer if multisig_threshold == 0 else create_multisig_signer(
            stark_signer, secp_signer))
    deployed_account.signer = account_signer
    await execute_calls(deployed_account, balanceof_call, execute_v3=is_v3)


@pytest.mark.parametrize("init_from_3rd_party_account", [True, False])
@pytest.mark.parametrize("is_v3", [True, False])
@pytest.mark.parametrize([
    "secp256r1_keypair",
    "is_webauthn",
    "multisig_threshold",
    "withdrawal_limit_low",
    "fee_rate",
], [
    (None, False, 0, 0, 0),
    (generate_secp256r1_keypair(), False, 2, 0, 0),
    (generate_secp256r1_keypair(), True, 2, 0, 0),
    (generate_secp256r1_keypair(), False, 0, 0, 0),
    (generate_secp256r1_keypair(), True, 0, 0, 0),
    (generate_secp256r1_keypair(), False, 0, 50 * USDC, 100 * USDC),
    (generate_secp256r1_keypair(), True, 0, 50 * USDC, 100 * USDC),
    (generate_secp256r1_keypair(), False, 2, 50 * USDC, 100 * USDC),
    (generate_secp256r1_keypair(), True, 2, 50 * USDC, 100 * USDC),
])
@pytest.mark.asyncio
async def test_deployment_from_malicious_factory_and_init_from_account(
        init_starknet, account_declare, declare_deploy_v1,
        account_contracts_str, init_account_factory,
        init_from_3rd_party_account, is_v3, secp256r1_keypair, is_webauthn,
        multisig_threshold, withdrawal_limit_low, fee_rate):
    devnet_url, devnet_client, devnet_account = init_starknet
    account_factory_address, malicious_factory_chash = init_account_factory
    account_chash, base_account_chash, _, _ = account_declare
    base_account_sierra_str, _, _, _ = account_contracts_str
    devnet_account: Account
    devnet_client: FullNodeClient

    factor_upgrade_txn = await devnet_account.execute_v1(
        Call(
            to_addr=account_factory_address,
            selector=get_selector_from_name('upgrade'),
            calldata=[malicious_factory_chash],
        ),
        auto_estimate=True,
    )
    await devnet_client.wait_for_tx(factor_upgrade_txn.transaction_hash)

    stark_privk = random.randint(1, 10**10)
    stark_pubk = private_to_stark_key(stark_privk)
    stark_signer = create_stark_signer(stark_privk)
    strong_signer_type = WEBAUTHN_SIGNER_TYPE if is_webauthn else SECP256R1_SIGNER_TYPE

    strong_signer_field = [0, 0, 0, 0, 0] if secp256r1_keypair is None else [
        strong_signer_type, *flatten_seq(secp256r1_keypair[1])
    ]
    aux_data = [
        account_chash,
        *strong_signer_field,
        multisig_threshold,
        withdrawal_limit_low,
        fee_rate,
        fee_rate,
        DEVNET_CHAIN_ID,
    ]
    aux_hash = poseidon_hash_many(aux_data)
    aux_sig = message_signature(aux_hash, stark_privk)

    additional_depl_data = [*aux_data, *aux_sig]
    deployment_call = Call(
        to_addr=account_factory_address,
        selector=get_selector_from_name("deploy_braavos_account"),
        calldata=[
            stark_pubk,
            len(additional_depl_data), *additional_depl_data
        ])
    expected_address = compute_address(class_hash=base_account_chash,
                                       salt=stark_pubk,
                                       constructor_calldata=[stark_pubk],
                                       deployer_address=0)
    exec_txn = await devnet_account.execute_v1(
        calls=deployment_call,
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    exec = await devnet_account.execute_v1(
        Call(
            to_addr=utils_v2.STRK_ADDRESS if is_v3 else ETH_TOKEN_ADDRESS,
            selector=get_selector_from_name("transfer"),
            calldata=[
                expected_address,
                105 * 10**18,
                0,
            ],
        ),
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec.transaction_hash)

    deployed_account = Account(
        client=devnet_client,
        address=expected_address,
        key_pair=KeyPair.from_private_key(stark_privk),
        chain=DEVNET_CHAIN_ID,
    )

    # the account is in a hanging state - the ctor was called and the account exists on chain
    # but the initializer was not called by the malicious factory
    deployed_account_chash = await devnet_client.get_class_hash_at(
        deployed_account.address)
    assert deployed_account_chash == base_account_chash, "wrong account chash between ctor and init"

    secp_signer = None if secp256r1_keypair is None else (
        create_webauthn_signer(secp256r1_keypair[0])
        if is_webauthn else create_secp256r1_signer(secp256r1_keypair[0]))
    account_signer = deployed_account.signer if secp_signer is None else (
        secp_signer if multisig_threshold == 0 else create_multisig_signer(
            stark_signer, secp_signer))
    balanceof_call = Call(
        to_addr=int(FEE_CONTRACT_ADDRESS, 16),
        selector=get_selector_from_name('balanceOf'),
        calldata=[deployed_account.address],
    )
    await assert_execute_fails_with_signer(
        deployed_account,
        balanceof_call,
        account_signer,
        'NOT_IMPLEMENTED',
    )

    init_account_call = Call(
        to_addr=deployed_account.address,
        selector=get_selector_from_name('initializer_from_factory'),
        calldata=[
            stark_pubk,
            len(additional_depl_data), *additional_depl_data
        ],
    )
    if init_from_3rd_party_account:
        # to verify that the account is not bricked - another account will now initialize the account
        await execute_calls(devnet_account,
                            init_account_call,
                            execute_v3=is_v3)
    else:
        # verifying that only a stark signature with size 2 is accepted at this stage
        await assert_execute_fails_with_signer(
            deployed_account,
            init_account_call,
            create_legacy_stark_signer_oversized_length(stark_privk),
            'INVALID_TXN_SIG',
        )
        # to verify that the account is not bricked - we check that a call within
        await execute_calls(deployed_account,
                            init_account_call,
                            execute_v3=is_v3)

    deployed_account_chash = await devnet_client.get_class_hash_at(
        deployed_account.address)
    assert deployed_account_chash == account_chash, "wrong account chash after init"

    deployed_account.signer = account_signer
    await execute_calls(deployed_account, balanceof_call, execute_v3=is_v3)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "src6_supported",
    ],
    [
        [True],
        [False],
    ],
    ids=[
        "src6_supported",
        "src6_not_supported",
    ],
)
async def test_upgrade(
    init_starknet,
    account_declare,
    account_deployer,
    upgrade_test_declare,
    src6_supported,
):
    devnet_client: FullNodeClient
    _, devnet_client, _ = init_starknet
    account_chash, _, _, _ = account_declare
    account_deployer = account_deployer
    upgrade_declare = upgrade_test_declare
    stark_privk = random.randint(1, 10**10)
    stark_pubk = private_to_stark_key(stark_privk)
    account, deploy_txn_hash = await account_deployer(stark_privk,
                                                      None,
                                                      0,
                                                      is_webauthn=False)
    account: Account
    if src6_supported:
        await account.execute_v1(
            Call(to_addr=account.address,
                 selector=get_selector_from_name('upgrade'),
                 calldata=[upgrade_declare[0]]),
            auto_estimate=True,
        )
        migrated_storage = await devnet_client.get_storage_at(
            account.address, get_selector_from_name("storage_migration_ver"))
        assert migrated_storage == int.from_bytes(b'001.002.000', 'big')
    else:
        with pytest.raises(Exception):
            await account.execute_v1(
                Call(to_addr=account.address,
                     selector=get_selector_from_name('upgrade'),
                     calldata=[upgrade_declare[1]]),
                auto_estimate=True,
            )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "secp256r1_keypair",
        "multisig_threshold",
        "stark_pub_key_override",
        "deploy_signer_override",
        "is_webauthn",
        "withdrawal_limit_low",
        "fee_rate",
        "expected_error",
    ],
    [
        (None, 0, 0, None, False, 0, 0, 'INVALID_DEPLOYMENT_SIG'),
        (None, 0, None,
         lambda chash: [31337, 31338, chash, 0, 0, 0, 0, 0, 31337, 31338],
         False, 0, 0, 'INVALID_DEPLOYMENT_SIG'),
        (None, 0, None, lambda chash: [0, 0, chash, 0, 0, 0, 0, 0, 0, 0],
         False, 0, 0, 'INVALID_DEPLOYMENT_SIG'),
        (None, 1, None, None, False, 0, 0, 'INVALID_MULTISIG_THRESHOLD'),
        (None, 2, None, None, False, 0, 0, 'INVALID_MULTISIG_THRESHOLD'),
        (generate_secp256r1_keypair(), 1, None, None, False, 0, 0,
         'INVALID_MULTISIG_THRESHOLD'),
        (generate_secp256r1_keypair(), 3, None, None, False, 0, 0,
         'INVALID_MULTISIG_THRESHOLD'),
        (generate_secp256r1_keypair(), 1, None, None, True, 0, 0,
         'INVALID_MULTISIG_THRESHOLD'),
        (generate_secp256r1_keypair(), 3, None, None, True, 0, 0,
         'INVALID_MULTISIG_THRESHOLD'),
        ((None, [1234, 4321, 5678, 8765]), 0, None, None, False, 0, 0, None),
        ((None, [1234, 4321, *generate_secp256r1_keypair()[1][1]
                 ]), 0, None, None, False, 0, 0, None),
        ((None, [*generate_secp256r1_keypair()[1][0], 5678, 8765
                 ]), 0, None, None, False, 0, 0, None),
        ((None, [1234, 4321, 5678, 8765]), 0, None, None, True, 0, 0, None),
        ((None, [1234, 4321, *generate_secp256r1_keypair()[1][1]
                 ]), 0, None, None, True, 0, 0, None),
        ((None, [*generate_secp256r1_keypair()[1][0], 5678, 8765
                 ]), 0, None, None, True, 0, 0, None),
        (None, 0, None, None, False, ETHER, ETHER,
         'INVALID_WITHDRAWAL_LIMIT_LOW'),
        (generate_secp256r1_keypair(), 0, None, None, False, ETHER, 0,
         'MISSING_RATE'),
    ],
    ids=[
        "stark_pub_key_is_0",
        "basic_stark_wrong_sig",
        "basic_stark_rs_zero_sig",
        "multisig_1_with_only_stark",
        "multisig_2_with_only_stark",
        "multisig_1_with_secp256r1",
        "multisig_3_with_secp256r1",
        "multisig_1_with_secp256r1_webauthn",
        "multisig_3_with_secp256r1_webauthn",
        "invalid_secp256r1_pubk",
        "invalid_secp256r1_pubk_x",
        "invalid_secp256r1_pubk_y",
        "invalid_secp256r1_pubk_webauthn",
        "invalid_secp256r1_pubk_x_webauthn",
        "invalid_secp256r1_pubk_y_webauthn",
        "low_withdrawal_limit_set_with_only_stark",
        "low_withdrawal_limit_set_without_fee_rate",
    ],
)
async def test_invalid_account_deployment(
    account_declare,
    account_deployer,
    secp256r1_keypair,
    multisig_threshold,
    stark_pub_key_override,
    deploy_signer_override,
    is_webauthn,
    withdrawal_limit_low,
    fee_rate,
    expected_error,
):
    account_chash, _, _, _ = account_declare
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    secp256r1_pubk = None if secp256r1_keypair is None else flatten_seq(
        secp256r1_keypair[1])
    if deploy_signer_override is not None:
        deploy_signer = namedtuple(
            "_DeploySigner",
            ["sign_transaction"
             ])(lambda depl_account: deploy_signer_override(account_chash))
    else:
        deploy_signer = None
    with pytest.raises(Exception):
        _ = await account_deployer(
            stark_privk,
            secp256r1_pubk,
            multisig_threshold,
            withdrawal_limit_low=withdrawal_limit_low,
            fee_rate=fee_rate,
            stark_pub_key_override=stark_pub_key_override,
            deploy_signer=deploy_signer,
            is_webauthn=is_webauthn)


@pytest.mark.asyncio
async def test_fail_initializer_after_deployment(account_deployer, ):
    account_deployer = account_deployer
    stark_privk = random.randint(1, 10**10)
    account, _ = await account_deployer(stark_privk, None, 0)
    account: Account
    with pytest.raises(Exception):
        await account.execute_v1(
            Call(to_addr=account.address,
                 selector=get_selector_from_name('initializer'),
                 calldata=[31337]),
            auto_estimate=True,
        )
