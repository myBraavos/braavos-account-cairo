import asyncio
from collections import namedtuple
from contextlib import contextmanager
import os
from pathlib import Path
import pytest
import pytest_asyncio
import time
import subprocess
import random

from e2e.utils.utils import *
import e2e.utils.utils_v2 as utils_v2
from e2e.utils.utils_v2 import ACCOUNTS
from e2e.utils.typed_data import get_test_gas_sponsored_session_execution_object, get_test_session_execution_object, OutsideExecution

from poseidon_py.poseidon_hash import poseidon_hash_many
from starknet_py.constants import FEE_CONTRACT_ADDRESS
from starknet_py.hash.class_hash import compute_class_hash
from starknet_py.net.client_errors import ClientError
from starknet_py.net.account.account import Account, KeyPair
from starknet_py.net.client_models import Call
from starknet_py.net.full_node_client import FullNodeClient
from starknet_py.hash.address import compute_address
from starknet_py.hash.selector import get_selector_from_name
from starknet_py.hash.transaction import compute_deploy_account_transaction_hash, compute_deploy_account_v3_transaction_hash
from starknet_py.hash.utils import message_signature
from starknet_py.net.schemas.rpc.contract import ContractClassSchema
from starknet_py.net.models.chains import StarknetChainId
from starknet_py.net.models.transaction import DeployAccount
from starknet_py.contract import Contract
from starknet_py.net.udc_deployer.deployer import Deployer
from starknet_py.hash.transaction import TransactionHashPrefix


@contextmanager
def none_context():
    try:
        yield None
    finally:
        pass


@pytest.fixture(scope="module")
def event_loop():
    return asyncio.get_event_loop()


@pytest.fixture(scope="module")
def account_contracts_str():
    base_account_prefix = "target/dev/braavos_account_BraavosBaseAccount"
    account_prefix = "target/dev/braavos_account_BraavosAccount"
    base_account_sierra_str, base_account_casm_str = get_contract_str(
        base_account_prefix, )
    account_sierra_str, account_casm_str = get_contract_str(account_prefix, )
    return (
        base_account_sierra_str,
        base_account_casm_str,
        account_sierra_str,
        account_casm_str,
    )


@pytest.fixture(scope="module")
def rate_service_contract_strings():
    rate_service_prefix = "services/rate_service/target/dev/rate_service_RateService"
    rate_service_sierra_str, rate_service_casm_str = get_contract_str(
        rate_service_prefix, )
    return rate_service_sierra_str, rate_service_casm_str


@pytest_asyncio.fixture(scope="module")
async def init_starknet():

    sn_devnet_url = "http://127.0.0.1:5050"
    sn_devnet_client = FullNodeClient(node_url=f"{sn_devnet_url}/rpc")

    sn_devnet_client_wait_for_tx_orig = sn_devnet_client.wait_for_tx

    async def wait_for_tx_short(tx_hash):
        return await sn_devnet_client_wait_for_tx_orig(tx_hash,
                                                       check_interval=0.1)

    sn_devnet_client.wait_for_tx = wait_for_tx_short

    # Katana
    '''
    | Account address |  0x5686a647a9cdd63ade617e0baf3b364856b813b508f03903eb58a7e622d5855
    | Private key     |  0x33003003001800009900180300d206308b0070db00121318d17b5e6262150b
    | Public key      |  0x4c0f884b8e5b4f00d97a3aad26b2e5de0c0c76a555060c837da2e287403c01d
    '''
    # devnet_account_address = 0x5686a647a9cdd63ade617e0baf3b364856b813b508f03903eb58a7e622d5855
    # devnet_account_privk = 0x33003003001800009900180300d206308b0070db00121318d17b5e6262150b
    # starknet-devnet-rs
    '''
    | Account address |  0x64b48806902a367c8598f4f95c305e8c1a1acba5f082d294a43793113115691
    | Private key     |  0x71d7bb07b9a64f6f78ac4c816aff4da9
    | Public key      |  0x39d9e6ce352ad4530a0ef5d5a18fd3303c3606a7fa6ac5b620020ad681cc33b
    '''
    devnet_account_address = 0x64b48806902a367c8598f4f95c305e8c1a1acba5f082d294a43793113115691
    devnet_account_privk = 0x71d7bb07b9a64f6f78ac4c816aff4da9

    sn_devnet_account = Account(
        address=devnet_account_address,
        client=sn_devnet_client,
        key_pair=KeyPair.from_private_key(devnet_account_privk),
        chain=DEVNET_CHAIN_ID)

    process = subprocess.Popen(
        [
            os.environ['STARKNET_DEVNET'],
            "--seed",
            "0",
            "--initial-balance",
            f"{10**6 * 10**18}",
        ],
        env=dict(os.environ),
        preexec_fn=os.setsid,
    )
    time.sleep(5)
    yield sn_devnet_url, sn_devnet_client, sn_devnet_account
    process.terminate()


@pytest_asyncio.fixture(scope="module")
def declare_deploy_v1():

    async def _declare_deploy_v1(compiled_contract_path,
                                 devnet_account,
                                 salt=0,
                                 unique=False):

        compiled_contract_content = Path(compiled_contract_path).read_text()
        compiled_contract = ContractClassSchema().loads(
            compiled_contract_content, unknown="exclude")
        class_hash = compute_class_hash(compiled_contract)

        class_exists = True
        try:
            await devnet_account.client.get_class_by_hash(class_hash)
        except ClientError:
            class_exists = False

        if class_exists:
            deploy_result = await Contract.deploy_contract_v1(
                account=devnet_account,
                class_hash=class_hash,
                abi=compiled_contract.abi,
                constructor_args=[],
                max_fee=int(1e17))
            await devnet_account.client.wait_for_tx(deploy_result.hash)
            return deploy_result.deployed_contract

        else:
            declare_result = await Contract.declare_v1(
                account=devnet_account,
                compiled_contract=compiled_contract_content,
                max_fee=int(1e17),
            )
            await devnet_account.client.wait_for_tx(declare_result.hash)
            deploy_result = await declare_result.deploy_v1(max_fee=int(1e16),
                                                           constructor_args=[],
                                                           unique=unique,
                                                           salt=salt)
            await devnet_account.client.wait_for_tx(deploy_result.hash)
            return deploy_result.deployed_contract

    return _declare_deploy_v1


@pytest_asyncio.fixture(scope="module")
def do_single_bypass_multicall(init_starknet, init_pricing_contract):
    pricing_contract_address, _, _ = init_pricing_contract

    async def _do_single_bypass_multicall(amount,
                                          token_address,
                                          account,
                                          bypass_signer,
                                          execute_v3=False):
        devnet_url, devnet_client, devnet_account = init_starknet
        temp = account.signer
        account.signer = bypass_signer
        max_fee = int(0.1 * 10**18)

        # multicall is an approve + call to configured contract
        approve_bypass_call = Call(
            to_addr=token_address,
            selector=get_selector_from_name("approve"),
            calldata=[pricing_contract_address, *to_uint256(amount)])
        custom_call = Call(
            to_addr=pricing_contract_address,
            selector=get_selector_from_name("get_average_price"),
            calldata=[0, 0],
        )
        calls = [
            approve_bypass_call,
            custom_call,
        ]

        if execute_v3:
            exec_txn = await account.execute_v3(
                calls=calls,
                l1_resource_bounds=ResourceBounds(
                    max_amount=int(max_fee / (100 * 10**9)),
                    max_price_per_unit=100 * 10**9 + 1,
                ),
            )
        else:
            exec_txn = await account.execute_v1(calls=calls, max_fee=max_fee)

        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

        account.signer = temp

    return _do_single_bypass_multicall


@pytest_asyncio.fixture(scope="module")
def do_double_bypass_multicall(init_starknet, init_pricing_contract):
    pricing_contract_address, _, _ = init_pricing_contract

    async def _do_double_bypass_multicall(amount1,
                                          token_address1,
                                          amount2,
                                          token_address2,
                                          account,
                                          bypass_signer,
                                          execute_v3=False):
        devnet_url, devnet_client, devnet_account = init_starknet
        temp = account.signer
        account.signer = bypass_signer
        max_fee = int(0.1 * 10**18)

        # multicall is an approve + call to configured contract
        approve_bypass_call1 = Call(
            to_addr=token_address1,
            selector=get_selector_from_name("approve"),
            calldata=[pricing_contract_address, *to_uint256(amount1)])
        approve_bypass_call2 = Call(
            to_addr=token_address2,
            selector=get_selector_from_name("approve"),
            calldata=[pricing_contract_address, *to_uint256(amount2)])
        custom_call = Call(
            to_addr=pricing_contract_address,
            selector=get_selector_from_name("get_average_price"),
            calldata=[0, 0],
        )
        calls = [
            approve_bypass_call1,
            approve_bypass_call2,
            custom_call,
        ]

        if execute_v3:
            exec_txn = await account.execute_v3(
                calls=calls,
                l1_resource_bounds=ResourceBounds(
                    max_amount=int(max_fee / (100 * 10**9)),
                    max_price_per_unit=100 * 10**9 + 1,
                ),
            )
        else:
            exec_txn = await account.execute_v1(calls=calls, max_fee=max_fee)

        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

        account.signer = temp

    return _do_double_bypass_multicall


@pytest_asyncio.fixture(scope="module")
def do_bypass(init_starknet):

    async def _do_bypass(token,
                         amount,
                         account,
                         bypass_signer,
                         call_type,
                         execute_v3=False):
        devnet_url, devnet_client, devnet_account = init_starknet
        temp = account.signer
        account.signer = bypass_signer
        max_fee = int(0.1 * 10**18)

        transfer_bypass_call = Call(
            to_addr=token,
            selector=get_selector_from_name(call_type),
            calldata=[devnet_account.address, *to_uint256(amount)])
        if execute_v3:
            exec_txn = await account.execute_v3(
                calls=transfer_bypass_call,
                l1_resource_bounds=ResourceBounds(
                    max_amount=int(max_fee / (100 * 10**9)),
                    max_price_per_unit=100 * 10**9 + 1,
                ),
            )
        else:
            exec_txn = await account.execute_v1(calls=transfer_bypass_call,
                                                max_fee=max_fee)
        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

        account.signer = temp

    return _do_bypass


@pytest_asyncio.fixture(scope="module")
def set_and_assert_high_threshold(init_starknet):

    async def _set_and_assert_high_threshold(high_threshold, account):
        _, devnet_client, _ = init_starknet
        set_withdrawal_limit_high_call = Call(
            to_addr=account.address,
            selector=get_selector_from_name("set_withdrawal_limit_high"),
            calldata=[high_threshold],
        )
        exec_txn = await account.execute_v1(
            calls=set_withdrawal_limit_high_call,
            max_fee=int(0.1 * 10**18),
        )

        await devnet_client.wait_for_tx(exec_txn.transaction_hash)
        exec_txn_receipt = await devnet_client.get_transaction_receipt(
            exec_txn.transaction_hash)
        assert (txn_receipt_contains_event(
            exec_txn_receipt,
            [get_selector_from_name("WithdrawalLimitHighSet")],
            [high_threshold],
            True,
        ) is True), "no withdrawal limit set"

    return _set_and_assert_high_threshold


@pytest_asyncio.fixture(scope="module")
def set_and_assert_low_threshold(init_starknet):

    async def _set_and_assert_low_threshold(low_threshold, account):
        _, devnet_client, _ = init_starknet
        set_withdrawal_limit_low_call = Call(
            to_addr=account.address,
            selector=get_selector_from_name("set_withdrawal_limit_low"),
            calldata=[low_threshold],
        )
        exec_txn = await account.execute_v1(
            calls=set_withdrawal_limit_low_call,
            max_fee=int(0.1 * 10**18),
        )

        await devnet_client.wait_for_tx(exec_txn.transaction_hash)
        exec_txn_receipt = await devnet_client.get_transaction_receipt(
            exec_txn.transaction_hash)
        assert (txn_receipt_contains_event(
            exec_txn_receipt,
            [get_selector_from_name("WithdrawalLimitLowSet")],
            [low_threshold],
            True,
        ) is True), "no withdrawal limit set"

    return _set_and_assert_low_threshold


@pytest_asyncio.fixture(scope="module")
def generate_token(init_starknet, declare_deploy_v1):

    async def _generate_token(name, decimals, salt):
        devnet_url, devnet_client, devnet_account = init_starknet
        devnet_account: Account
        devnet_client: FullNodeClient
        res = await declare_deploy_v1("e2e/contracts/ERC20.json",
                                      devnet_account,
                                      salt=salt)
        res: Contract
        exec_tx = await devnet_account.execute_v1(
            Call(
                to_addr=res.address,
                selector=get_selector_from_name("initialize"),
                calldata=[4, name, name, decimals, devnet_account.address],
            ),
            max_fee=int(0.1 * 10**18),
        )
        await devnet_client.wait_for_tx(exec_tx.transaction_hash)

        mint_tx = await devnet_account.execute_v1(
            Call(
                to_addr=res.address,
                selector=get_selector_from_name("permissionedMint"),
                calldata=[
                    devnet_account.address,
                    *(to_uint256(ETHER * 10000)),
                ],
            ),
            max_fee=int(0.1 * 10**18),
        )
        await devnet_client.wait_for_tx(mint_tx.transaction_hash)

        return res

    return _generate_token


@pytest_asyncio.fixture(scope="module")
async def init_account_factory(init_starknet, account_declare):
    devnet_url, devnet_client, devnet_account = init_starknet
    _, base_account_chash, _, _ = account_declare

    account_factory_chash = await declare_v2(
        devnet_client,
        devnet_account,
        "e2e/contracts/braavos_account_factory.sierra.json",
        "e2e/contracts/braavos_account_factory.casm.json",
    )

    deployment = Deployer().create_contract_deployment(
        class_hash=account_factory_chash,
        salt=0,
        cairo_version=1,
    )
    exec = await devnet_account.execute_v1(deployment.call, auto_estimate=True)
    await devnet_client.wait_for_tx(exec.transaction_hash)

    factory_init_txn = await devnet_account.execute_v1(
        Call(
            to_addr=deployment.address,
            selector=get_selector_from_name('initializer'),
            calldata=[devnet_account.address, base_account_chash],
        ),
        auto_estimate=True,
    )
    await devnet_client.wait_for_tx(factory_init_txn.transaction_hash)

    # this factory impl is identical to the regular one, but does not call initialize after ctor
    malicious_factory_chash = await declare_v2(
        devnet_client,
        devnet_account,
        "e2e/contracts/braavos_account_factory_malicious.contract_class.json",
        "e2e/contracts/braavos_account_factory_malicious.compiled_contract_class.json",
    )

    return deployment.address, malicious_factory_chash


@pytest_asyncio.fixture(scope="module")
async def init_pricing_contract(init_starknet):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_account: Account
    devnet_client: FullNodeClient
    pricing_decl_chash = await declare_v2(
        devnet_client,
        devnet_account,
        "e2e/contracts/myswapv3_PoolPrice.sierra.json",
        "e2e/contracts/myswapv3_PoolPrice.casm.json",
    )

    deployment = Deployer().create_contract_deployment(
        class_hash=pricing_decl_chash,
        salt=0,
        cairo_version=1,
    )
    exec = await devnet_account.execute_v1(deployment.call, auto_estimate=True)
    await devnet_client.wait_for_tx(exec.transaction_hash)

    # Setup pricing contract
    exec = await devnet_account.execute_v1(
        Call(
            to_addr=deployment.address,
            selector=get_selector_from_name("initializer"),
            calldata=[devnet_account.address, 0x31337],
        ),
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec.transaction_hash)

    mock_decl_chash = await declare_v2(
        devnet_client,
        devnet_account,
        "e2e/contracts/price_contract_test.sierra.json",
        "e2e/contracts/price_contract_test.casm.json",
    )

    # Upgrade to mock
    exec = await devnet_account.execute_v1(
        Call(
            to_addr=deployment.address,
            selector=get_selector_from_name("upgrade"),
            calldata=[mock_decl_chash],
        ),
        max_fee=int(0.1 * 10**18),
    )
    await devnet_client.wait_for_tx(exec.transaction_hash)

    async def _set_price(pool_key, seconds_ago, price):
        set_exec = await devnet_account.execute_v1(
            Call(
                to_addr=deployment.address,
                selector=get_selector_from_name("set_price_for_pool_key"),
                calldata=[pool_key, seconds_ago, *to_uint256(price)],
            ),
            max_fee=int(0.1 * 10**18),
        )
        await devnet_client.wait_for_tx(set_exec.transaction_hash)

    async def _get_price(pool_key, seconds_ago):
        return await devnet_client.call_contract(
            Call(
                to_addr=deployment.address,
                selector=get_selector_from_name("get_average_price"),
                calldata=[pool_key, seconds_ago],
            ), )

    USDC_ADDR = 0x053C91253BC9682C04929CA02ED00B3E423F6710D2EE7E0D5EBB06F3ECF368A8
    await _set_price(
        compute_myswap_cl_pool_key(int(FEE_CONTRACT_ADDRESS, 16), USDC_ADDR,
                                   500),
        86400,
        compute_myswap_cl_to_usdc_price(target_rate_usdc_for_token=100 // 1,
                                        token_decimal=18,
                                        is_usdc_token0=False),
    )

    STARK_ADDR = 0x04718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D
    await _set_price(
        compute_myswap_cl_pool_key(STARK_ADDR, USDC_ADDR, 500),
        86400,
        compute_myswap_cl_to_usdc_price(target_rate_usdc_for_token=100 // 1,
                                        token_decimal=18,
                                        is_usdc_token0=False),
    )

    return deployment.address, _set_price, _get_price


@pytest_asyncio.fixture(scope="module")
async def usdc_token(generate_token):
    return await generate_token("USDC", 6, salt=0)


@pytest_asyncio.fixture(scope="module")
async def mock_usdc_threshold_token(generate_token):
    return await generate_token("USDC2", 6, salt=2)


@pytest_asyncio.fixture(scope="module")
async def pepe_token(generate_token):
    return await generate_token("PEPE", 18, salt=1)


@pytest_asyncio.fixture(scope="module")
async def sha256_cairo0_declare(init_starknet):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_account: Account
    devnet_client: FullNodeClient
    with open("e2e/contracts/sha256_cairo0.json", mode="r",
              encoding="utf8") as compiled_contract:
        compiled_contract_content = compiled_contract.read()
        chash = compute_class_hash(ContractClassSchema().loads(
            compiled_contract_content, unknown="exclude"))

        class_exists = True
        try:
            await devnet_account.client.get_class_by_hash(chash)
        except ClientError:
            class_exists = False

        if not class_exists:
            declare_tx = await devnet_account.sign_declare_v1(
                compiled_contract=compiled_contract_content,
                max_fee=int(0.1 * 10**18),
            )
            decl = await devnet_client.declare(transaction=declare_tx)
            await devnet_client.wait_for_tx(decl.transaction_hash)
        return chash


@pytest_asyncio.fixture(scope="module")
async def upgrade_test_declare(init_starknet):
    _, devnet_client, devnet_account = init_starknet
    devnet_account: Account
    devnet_client: FullNodeClient

    happy_path_chash = await declare_v2(
        devnet_client,
        devnet_account,
        "./e2e/contracts/upgrade_test.sierra.json",
        "./e2e/contracts/upgrade_test.casm.json",
    )

    fail_src6_chash = await declare_v2(
        devnet_client,
        devnet_account,
        "./e2e/contracts/upgrade_test_fail_src6.sierra.json",
        "./e2e/contracts/upgrade_test_fail_src6.casm.json",
    )
    return happy_path_chash, fail_src6_chash


@pytest_asyncio.fixture(scope="module")
async def account_declare(init_starknet, account_contracts_str,
                          sha256_cairo0_declare):
    _ = sha256_cairo0_declare
    (
        base_account_sierra_str,
        base_account_casm_str,
        account_sierra_str,
        account_casm_str,
    ) = account_contracts_str
    _, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    devnet_account: Account

    account_sierra_chash = await utils_v2.declare(devnet_client,
                                                  devnet_account,
                                                  account_sierra_str,
                                                  account_casm_str)
    base_account_sierra_chash = await utils_v2.declare(
        devnet_client, devnet_account, base_account_sierra_str,
        base_account_casm_str)
    account_cairo0_chash = await utils_v2.declare_v0(
        devnet_client, devnet_account, "e2e/contracts/account_cairo0.json")
    proxy_cairo0_chash = await utils_v2.declare_v0(
        devnet_client, devnet_account, "e2e/contracts/proxy_cairo0.json")

    return (
        account_sierra_chash,
        base_account_sierra_chash,
        account_cairo0_chash,
        proxy_cairo0_chash,
    )


@pytest_asyncio.fixture(scope="module")
async def account_deployer(
    init_starknet,
    account_declare,
    usdc_token,
    init_pricing_contract,
):
    account_chash, base_account_chash, _, _ = account_declare
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    devnet_account: Account

    def default_deployment_signer(
        stark_keypair: KeyPair,
        deploy_txn: DeployAccount,
        address: int,
        strong_signer_type=0,
        secp256r1_signer=[0, 0, 0, 0],
        multisig_threshold=0,
        withdrawal_limit_low=0,
        eth_fee_rate=0,
        stark_fee_rate=0,
        deploy_with_v3=False,
    ):
        secp256r1_signer = [0, 0, 0, 0
                            ] if secp256r1_signer is None else secp256r1_signer
        if deploy_with_v3:
            deploy_txn_hash = compute_deploy_account_v3_transaction_hash(
                common_fields=deploy_txn.get_common_fields(
                    tx_prefix=TransactionHashPrefix.DEPLOY_ACCOUNT,
                    address=address,
                    chain_id=DEVNET_CHAIN_ID),
                class_hash=deploy_txn.class_hash,
                constructor_calldata=deploy_txn.constructor_calldata,
                contract_address_salt=stark_keypair.public_key,
            )
        else:
            deploy_txn_hash = compute_deploy_account_transaction_hash(
                version=deploy_txn.version,
                contract_address=address,
                class_hash=deploy_txn.class_hash,
                constructor_calldata=deploy_txn.constructor_calldata,
                max_fee=deploy_txn.max_fee,
                nonce=deploy_txn.nonce,
                salt=stark_keypair.public_key,
                chain_id=DEVNET_CHAIN_ID)
        aux_hash = poseidon_hash_many([
            account_chash, strong_signer_type, *secp256r1_signer,
            multisig_threshold, withdrawal_limit_low, eth_fee_rate,
            stark_fee_rate, DEVNET_CHAIN_ID
        ])
        ret = [
            *message_signature(deploy_txn_hash, stark_keypair.private_key),
            account_chash,
            strong_signer_type,
            *secp256r1_signer,
            multisig_threshold,
            withdrawal_limit_low,
            eth_fee_rate,
            stark_fee_rate,
            DEVNET_CHAIN_ID,
            *message_signature(aux_hash, stark_keypair.private_key),
        ]
        return ret

    async def _account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_thresh,
        withdrawal_limit_low=0,
        eth_fee_rate=0,
        stark_fee_rate=0,
        stark_pub_key_override=None,
        deploy_signer=None,
        is_webauthn=False,
        erc20_address_to_transfer=None,
        deploy_with_v3=False,
    ):
        stark_keypair = KeyPair.from_private_key(stark_privk)
        stark_pubk = stark_pub_key_override if stark_pub_key_override is not None else stark_keypair.public_key
        ctor_calldata = [stark_pubk]
        account_address = compute_address(
            class_hash=base_account_chash,
            salt=stark_pubk,
            constructor_calldata=ctor_calldata,
        )

        for fee_token in [ETH_TOKEN_ADDRESS, utils_v2.STRK_ADDRESS]:
            exec = await devnet_account.execute_v1(
                Call(
                    to_addr=fee_token,
                    selector=get_selector_from_name("transfer"),
                    calldata=[
                        account_address,
                        105 * 10**18,
                        0,
                    ],
                ),
                max_fee=int(0.1 * 10**18),
            )
            await devnet_client.wait_for_tx(exec.transaction_hash)

        strong_signer_type = 0 if secp256r1_pubk in [
            None, [0, 0, 0, 0]
        ] else 5 if is_webauthn else 2

        if erc20_address_to_transfer is not None:
            exec = await devnet_account.execute_v1(
                Call(
                    to_addr=erc20_address_to_transfer,
                    selector=get_selector_from_name("transfer"),
                    calldata=[
                        account_address,
                        10**20,
                        0,
                    ],
                ),
                max_fee=int(0.1 * 10**18),
            )
            await devnet_client.wait_for_tx(exec.transaction_hash)

        if deploy_signer is None:
            deploy_signer = namedtuple(
                "_DeploySigner",
                ["sign_transaction"
                 ])(lambda depl_account: default_deployment_signer(
                     stark_keypair,
                     depl_account,
                     account_address,
                     strong_signer_type,
                     secp256r1_pubk or [0, 0, 0, 0],
                     multisig_thresh,
                     withdrawal_limit_low,
                     eth_fee_rate,
                     stark_fee_rate,
                     deploy_with_v3,
                 ))
        deployer_account = Account(
            client=devnet_client,
            address=account_address,
            signer=deploy_signer,
        )

        if deploy_with_v3:
            signed_account_depl = await deployer_account.sign_deploy_account_v3(
                class_hash=base_account_chash,
                contract_address_salt=stark_pubk,
                constructor_calldata=ctor_calldata,
                l1_resource_bounds=ResourceBounds(
                    max_amount=10**8,
                    max_price_per_unit=10**11,
                ),
                # auto_estimate=True,
            )
        else:
            signed_account_depl = await deployer_account.sign_deploy_account_v1(
                class_hash=base_account_chash,
                contract_address_salt=stark_pubk,
                constructor_calldata=ctor_calldata,
                auto_estimate=True,
            )
        account_depl = await devnet_client.deploy_account(signed_account_depl)
        await devnet_client.wait_for_tx(account_depl.transaction_hash)

        return Account(client=devnet_client,
                       address=account_address,
                       key_pair=stark_keypair,
                       chain=DEVNET_CHAIN_ID), account_depl.transaction_hash

    return _account_deployer


@pytest_asyncio.fixture(scope="module")
def get_spending_limit_amount_spent(init_starknet):

    async def _get_spending_limit_amount_spent(account, session_hash,
                                               token_address):
        _, devnet_client, _ = init_starknet

        low, _ = await devnet_client.call_contract(
            Call(
                to_addr=account.address,
                selector=get_selector_from_name(
                    "get_spending_limit_amount_spent"),
                calldata=[session_hash, token_address],
            ))
        return low

    return _get_spending_limit_amount_spent


@pytest_asyncio.fixture(scope="module")
def get_session_gas_spent(init_starknet):

    async def _get_session_gas_spent(account, session_hash):
        _, devnet_client, _ = init_starknet

        res = await devnet_client.call_contract(
            Call(
                to_addr=account.address,
                selector=get_selector_from_name("get_session_gas_spent"),
                calldata=[session_hash],
            ))
        return res[0]

    return _get_session_gas_spent


@pytest_asyncio.fixture(scope="module")
def get_fee_rate(init_starknet):

    async def _get_fee_rate(account, token_name="eth"):
        _, devnet_client, _ = init_starknet

        get_rate_result = await devnet_client.call_contract(
            Call(
                to_addr=account.address,
                selector=get_selector_from_name(
                    "get_fee_token_rate" if token_name ==
                    "eth" else "get_stark_fee_token_rate"),
                calldata=[],
            ))
        return get_rate_result[0]

    return _get_fee_rate


@pytest_asyncio.fixture(scope="module")
def get_daily_spend(init_starknet):

    async def _get_daily_spend(account):
        _, devnet_client, _ = init_starknet

        daily_spend_result = await devnet_client.call_contract(
            Call(
                to_addr=account.address,
                selector=get_selector_from_name("get_daily_spend"),
                calldata=[],
            ))
        return daily_spend_result[0]

    return _get_daily_spend


@pytest_asyncio.fixture(scope="module")
def get_required_signer(init_starknet):

    async def _get_required_signer(account: Account,
                                   call: Call,
                                   fee=0,
                                   version=1,
                                   use_signer=None):
        _, devnet_client, _ = init_starknet
        devnet_client: FullNodeClient
        orig_signer = account.signer
        if use_signer is not None:
            account.signer = use_signer
        invoke_txn = await account.sign_invoke_v1(
            Call(
                to_addr=account.address,
                selector=get_selector_from_name("get_required_signer"),
                calldata=[
                    1,
                    call.to_addr,
                    call.selector,
                    len(call.calldata),
                    *call.calldata,
                    # fee amount
                    fee,
                    # tx version
                    version
                ]),
            max_fee=int(0.1 * 10**18),
        )
        get_req_signer_txn = await account.sign_for_fee_estimate(invoke_txn)
        account.signer = orig_signer
        simul_res = await devnet_client.simulate_transactions(
            [get_req_signer_txn])
        return simul_res[0].transaction_trace.execute_invocation.calls[
            0].result[0]

    return _get_required_signer


@pytest_asyncio.fixture(scope="module")
def get_required_signer_of_bypass_call(init_starknet, get_required_signer):

    async def _get_required_signer_of_bypass_call(
        account: Account,
        amount=0,
        fee=0,
        version=1,
    ):
        _, devnet_client, devnet_account = init_starknet
        bypass_call = Call(
            to_addr=ETH_TOKEN_ADDRESS,
            selector=get_selector_from_name('transfer'),
            calldata=[devnet_account.address, *to_uint256(amount)],
        )
        return await get_required_signer(account,
                                         bypass_call,
                                         fee=fee,
                                         version=version)

    return _get_required_signer_of_bypass_call


@pytest_asyncio.fixture(scope="module")
def assert_required_signer(get_required_signer):

    async def _assert_required_signer(account: Account,
                                      call: Call,
                                      expected_signer: int,
                                      fee=0,
                                      use_signer=None):
        result = await get_required_signer(account, call, fee, 1, use_signer)
        assert result == expected_signer, 'Wrong required signer'
        result = await get_required_signer(account, call, fee, 3, use_signer)
        assert result == expected_signer, 'Wrong required signer'

    return _assert_required_signer


@pytest_asyncio.fixture(scope="module")
def assert_required_signer_of_bypass_call(get_required_signer):

    async def _assert_required_signer_of_bypass_call(account: Account,
                                                     expected_signer: int,
                                                     amount=0,
                                                     fee=0,
                                                     use_signer=None):
        bypass_call = Call(
            to_addr=ETH_TOKEN_ADDRESS,
            selector=get_selector_from_name('transfer'),
            calldata=[ETH_TOKEN_ADDRESS, *to_uint256(amount)],
        )
        result = await get_required_signer(account, bypass_call, fee, 1,
                                           use_signer)
        assert result == expected_signer, 'Wrong required signer'
        result = await get_required_signer(account, bypass_call, fee, 3,
                                           use_signer)
        assert result == expected_signer, 'Wrong required signer'

    return _assert_required_signer_of_bypass_call


@pytest_asyncio.fixture(scope="module")
def clean_token_config(init_starknet, init_pricing_contract):
    pricing_contract_address, _, _ = init_pricing_contract

    async def _clean_token_config(account,
                                  fake_usdc_address=None,
                                  add_custom_call_double=False):
        _, devnet_client, _ = init_starknet

        # removing all tokens which are hardcoded in the contract but do not exists
        # on testnet

        call_data = [
            3,
            # usdt
            False,
            0x068f5c6a61780768455de69077e07e89787839bf8166decfbf92b645209c0fb8,
            0,
            False,
            # wbtc
            False,
            0x03fe2b97c1fd336e750087d68b9b867997fd64a2661ff3ca5a7c771641e8e7ac,
            0,
            False,
            # usdc
            False,
            0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8,
            0,
            False,
            # 0
        ] if fake_usdc_address is None else [
            4,
            # usdt
            False,
            0x068f5c6a61780768455de69077e07e89787839bf8166decfbf92b645209c0fb8,
            0,
            False,
            # wbtc
            False,
            0x03fe2b97c1fd336e750087d68b9b867997fd64a2661ff3ca5a7c771641e8e7ac,
            0,
            False,
            # usdc
            False,
            0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8,
            0,
            False,
            # fake token
            True,
            fake_usdc_address,
            9999,
            False,
            # 0
        ]

        if add_custom_call_double:
            call_data.extend([
                1, pricing_contract_address,
                get_selector_from_name('get_average_price'), 2
            ])
        else:
            call_data.extend([
                1, pricing_contract_address,
                get_selector_from_name('get_average_price'), 1
            ])

        update_config_call = Call(
            to_addr=account.address,
            selector=get_selector_from_name('update_rate_config'),
            calldata=call_data)
        exec_txn = await account.execute_v1(
            calls=update_config_call,
            max_fee=int(0.1 * 10**18),
        )

        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

    return _clean_token_config


async def add_signers(signers_types, multisig_threshold, account,
                      devnet_client, signers):
    signers_num = len(signers_types)
    for i in range(signers_num):
        secp256r1_keypair = generate_secp256r1_keypair()
        secp256r1_pubk = flatten_seq(secp256r1_keypair[1])

        # set threshold when adding last signer
        threshold = 0 if i < signers_num - 1 else multisig_threshold

        add_secp256r1_call = Call(
            to_addr=account.address,
            selector=get_selector_from_name("add_secp256r1_signer"),
            calldata=[*secp256r1_pubk, signers_types[i], threshold],
        )
        exec_txn = await account.execute_v1(
            calls=add_secp256r1_call,
            max_fee=10**17,
        )
        await devnet_client.wait_for_tx(exec_txn.transaction_hash)

        signer = (create_secp256r1_signer(secp256r1_keypair[0])
                  if signers_types[i] == SECP256R1_SIGNER_TYPE else
                  create_webauthn_signer(secp256r1_keypair[0]))
        if (len(signers) == 0):
            account.signer = signer
        signers.append(signer)


@pytest.fixture(scope="module")
def setup_session_account_env(init_starknet, account_deployer,
                              set_and_assert_low_threshold,
                              set_and_assert_high_threshold):
    _, devnet_client, devnet_account = init_starknet

    async def _setup_session_acount_env(is_gas_sponsored_session,
                                        second_signer_type,
                                        multisig_threshold,
                                        existing_account=None,
                                        withdrawal_limit_low=0,
                                        withdrawal_limit_high=0,
                                        stark_privk_input=None):

        is_webauthn = second_signer_type == WEBAUTHN_SIGNER_TYPE
        account = existing_account
        if existing_account is None:
            stark_privk = random.randint(
                1, 10**10) if stark_privk_input is None else stark_privk_input
            secp256r1_keypair = generate_secp256r1_keypair()
            account, _ = await account_deployer(
                stark_privk,
                None if second_signer_type is None else flatten_seq(
                    secp256r1_keypair[1]),
                multisig_threshold,
                is_webauthn=is_webauthn)
            account: Account

            account.signer = create_signer(stark_privk, second_signer_type,
                                           secp256r1_keypair[0],
                                           multisig_threshold)
            account.secp256r1_keypair = secp256r1_keypair
            if withdrawal_limit_low > 0:
                await set_and_assert_low_threshold(withdrawal_limit_low,
                                                   account)

            if withdrawal_limit_high > 0:
                await set_and_assert_high_threshold(withdrawal_limit_high,
                                                    account)

        session_request_builder = get_test_gas_sponsored_session_execution_object if is_gas_sponsored_session else get_test_session_execution_object

        event_name = "GasSponsoredSessionStarted" if is_gas_sponsored_session else "SessionStarted"

        session_owner_identifier = devnet_account.address if is_gas_sponsored_session else devnet_account.signer.public_key

        dest_acc = Account(
            address=ACCOUNTS[2].address,
            client=devnet_client,
            key_pair=KeyPair.from_private_key(ACCOUNTS[2].pk),
            chain=DEVNET_CHAIN_ID,
        )

        async def execute_session_call(call, is_v3=True, max_fee=10**17):
            if is_gas_sponsored_session:
                return await execute_with_signer(devnet_account,
                                                 call,
                                                 devnet_account.signer,
                                                 is_v3=is_v3,
                                                 max_fee=max_fee)
            else:
                return await execute_with_signer(account,
                                                 call,
                                                 devnet_account.signer,
                                                 is_v3=is_v3,
                                                 max_fee=max_fee)

        return account, execute_session_call, session_request_builder, event_name, session_owner_identifier, dest_acc

    return _setup_session_acount_env


@pytest_asyncio.fixture(scope="module")
def send_outside_exec_tx_and_assert(init_starknet):
    _, devnet_client, devnet_account = init_starknet
    nonce = 0

    async def _send_outside_exec_tx_and_assert(account, calls, events):
        nonlocal nonce
        block = await devnet_client.get_block()
        block_timestamp = block.timestamp
        out_ex = OutsideExecution(account=account,
                                  calls=calls,
                                  execute_before=block_timestamp + 3600,
                                  execute_after=block_timestamp - 3600,
                                  nonce=nonce)

        tx = await devnet_account.execute_v1(
            out_ex.prepare_call(account.address),
            max_fee=10**17,
        )
        receipt = await devnet_client.wait_for_tx(tx.transaction_hash)
        for e in events:
            assert txn_receipt_contains_event(
                receipt,
                [
                    get_selector_from_name(e),
                ],
                [],
                match_data=True,
            ) is True, "missing event"

        nonce += 1

    return _send_outside_exec_tx_and_assert
