import e2e.utils.utils_v2 as utils_v2
from e2e.utils.utils_v2 import ACCOUNTS
from e2e.utils.fixtures import *
from e2e.utils.utils import get_contract_str

import pytest_asyncio
import pytest
import json

from starknet_py.net.account.account import Account
from starknet_py.contract import Contract


@pytest.fixture(scope="module")
def account_contracts_moa_str():
    account_prefix = "target/dev/braavos_account_BraavosMoaAccount"
    account_sierra_str, account_casm_str = get_contract_str(account_prefix, )
    signer_sierra_str, signer_casm_str = utils_v2.load_test_contract(
        "mockAccount")
    return (account_sierra_str, account_casm_str, signer_sierra_str,
            signer_casm_str)


@pytest_asyncio.fixture(scope="module")
async def account_declare_moa(init_starknet, account_contracts_moa_str):
    (
        account_sierra_str,
        account_casm_str,
        signer_sierra_str,
        signer_casm_str,
    ) = account_contracts_moa_str
    _, devnet_client, devnet_account = init_starknet
    account_sierra_chash = await utils_v2.declare(devnet_client,
                                                  devnet_account,
                                                  account_sierra_str,
                                                  account_casm_str)
    signer_sierra_chash = await utils_v2.declare(devnet_client, devnet_account,
                                                 signer_sierra_str,
                                                 signer_casm_str)
    return (
        account_sierra_chash,
        account_sierra_str,
        signer_sierra_chash,
        signer_sierra_str,
    )


@pytest_asyncio.fixture(scope="module")
async def account_deployer_moa(init_starknet, account_declare_moa,
                               init_pricing_contract):
    (
        account_chash,
        account_sierra_str,
        signer_chash,
        signer_sierra_str,
    ) = account_declare_moa
    _, _, devnet_account = init_starknet
    devnet_account: Account

    async def _account_deployer(signer_ids, threshold, top_up=True):
        signers = []
        signer_abi = json.loads(signer_sierra_str)["abi"]
        for i in signer_ids:
            ext_acc = await utils_v2.deploy_external_account(
                devnet_account, signer_chash, signer_abi, ACCOUNTS[i].pubk)
            signers.append(ext_acc)

        constructor_args = {"signers": signers, "threshold": threshold}

        deploy_result = await Contract.deploy_contract_v1(
            account=devnet_account,
            class_hash=account_chash,
            abi=json.loads(account_sierra_str)["abi"],
            constructor_args=constructor_args,
            max_fee=int(1e18),
            cairo_version=1,
        )

        await devnet_account.client.wait_for_tx(deploy_result.hash)

        if top_up:
            await utils_v2.transfer_eth(
                devnet_account,
                deploy_result.deployed_contract,
                10**19,
                devnet_account.client,
            )
            await utils_v2.transfer_strk(
                devnet_account,
                deploy_result.deployed_contract,
                10**19,
                devnet_account.client,
            )

        return deploy_result.deployed_contract, signers

    return _account_deployer


@pytest_asyncio.fixture()
async def prepare_signer(init_starknet,
                         account_deployer_moa) -> utils_v2.TestSigner:
    _, devnet_client, _ = init_starknet

    async def _prepare_signer(signer_ids, threshold, signer_pks):
        actual_signer_pks = [ACCOUNTS[i].pk for i in signer_pks]
        account, signers = await account_deployer_moa(signer_ids, threshold)
        signer = utils_v2.TestSigner(devnet_client, account, actual_signer_pks,
                                     signers)
        return signer

    return _prepare_signer


@pytest_asyncio.fixture()
async def prepare_simple_signer(prepare_signer):
    return await prepare_signer([0], 0, [0])
