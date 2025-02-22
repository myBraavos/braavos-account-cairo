import os
import subprocess
import time
import asyncio
import random
from e2e.rpc0_8.utils import (
    get_contract_str, declare_v3_direct_rpc, deploy_account_v3_direct_rpc,
    get_generic_resource_bounds, compute_deploy_account_v3_transaction_hash,
    ResourceBoundsMapping, invoke_v3_direct_rpc, fund_account, STRK_CONTRACT,
    DEVNET_CHAIN_ID, DEVNET_ACCOUNT_ADDRESS, DEVNET_ACCOUNT_PRIVK,
    generate_secp256r1_keypair, flatten_seq, call_contract_rpc)
import pytest
import pytest_asyncio
from starknet_py.net.client_models import (ResourceBounds, Call)
from starknet_py.hash.selector import get_selector_from_name
from starknet_py.hash.address import compute_address
from poseidon_py.poseidon_hash import poseidon_hash_many
from starknet_py.hash.utils import message_signature
from starknet_py.net.account.account import KeyPair


@pytest.fixture(scope="module")
def event_loop():
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="module")
async def init_starknet0_8():
    process = subprocess.Popen(
        [
            os.environ['STARKNET_DEVNET_0_8'], "--seed", "0", "--port", "5051",
            "--initial-balance", f"{10**6 * 10**18}", "--chain-id",
            "SN_SEPOLIA", "--account-class", "cairo0"
        ],
        env=dict(os.environ),
        preexec_fn=os.setsid,
    )
    time.sleep(5)
    yield
    process.terminate()


async def declare_v3(sierra_content: str, casm_content: str):

    resource_bounds = ResourceBoundsMapping(
        l1_gas=ResourceBounds(max_amount=int(10),
                              max_price_per_unit=int(100000000000)),
        l1_data_gas=ResourceBounds(max_amount=int(200),
                                   max_price_per_unit=int(100000000000)),
        l2_gas=ResourceBounds(max_amount=int(5000000000),
                              max_price_per_unit=int(100000000000)),
    )
    return await declare_v3_direct_rpc(DEVNET_ACCOUNT_ADDRESS,
                                       DEVNET_ACCOUNT_PRIVK, sierra_content,
                                       casm_content, resource_bounds)


@pytest_asyncio.fixture(scope="module")
async def account_declare(init_starknet0_8):
    init_starknet0_8

    base_account_prefix = "target/dev/braavos_account_BraavosBaseAccount"
    account_prefix = "target/dev/braavos_account_BraavosAccount"

    base_account_sierra_str, base_account_casm_str = get_contract_str(
        base_account_prefix)
    account_sierra_str, account_casm_str = get_contract_str(account_prefix)
    account_sierra_hash = await declare_v3(account_sierra_str,
                                           account_casm_str)
    base_account_sierra_hash = await declare_v3(base_account_sierra_str,
                                                base_account_casm_str)
    return (
        account_sierra_hash,
        base_account_sierra_hash,
    )


@pytest_asyncio.fixture(scope="module")
async def account_deployer(
    init_starknet0_8,
    account_declare,
):
    account_chash, base_account_chash = account_declare
    init_starknet0_8

    def default_deployment_signer(
        stark_keypair: KeyPair,
        deploy_txn,
        strong_signer_type=0,
        secp256r1_signer=[0, 0, 0, 0],
        multisig_threshold=0,
        withdrawal_limit_low=0,
        eth_fee_rate=0,
        stark_fee_rate=0,
    ):
        secp256r1_signer = [0, 0, 0, 0
                            ] if secp256r1_signer is None else secp256r1_signer
        deploy_txn_hash = compute_deploy_account_v3_transaction_hash(
            common_fields=deploy_txn["common_fields"],
            class_hash=deploy_txn["class_hash"],
            constructor_calldata=deploy_txn["constructor_calldata"],
            contract_address_salt=stark_keypair.public_key,
        )

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
        is_webauthn=False,
    ):
        stark_keypair = KeyPair.from_private_key(stark_privk)
        stark_pubk = stark_pub_key_override if stark_pub_key_override is not None else stark_keypair.public_key
        ctor_calldata = [stark_pubk]
        account_address = compute_address(
            class_hash=base_account_chash,
            salt=stark_pubk,
            constructor_calldata=ctor_calldata,
        )

        await fund_account(account_address, 105 * 10**18)

        strong_signer_type = 0 if secp256r1_pubk in [
            None, [0, 0, 0, 0]
        ] else 5 if is_webauthn else 2

        response = await deploy_account_v3_direct_rpc(
            address=account_address,
            sign_function=(lambda deploy_txn: default_deployment_signer(
                stark_keypair,
                deploy_txn,
                strong_signer_type,
                secp256r1_pubk or [0, 0, 0, 0],
                multisig_thresh,
                withdrawal_limit_low,
                eth_fee_rate,
                stark_fee_rate,
            )),
            stark_private_key=stark_privk,
            class_hash=base_account_chash,
            constructor_calldata=ctor_calldata,
            contract_address_salt=stark_pubk,
            resource_bounds=get_generic_resource_bounds(),
        )

        return account_address, response["transaction_hash"]

    return _account_deployer


@pytest.mark.asyncio
async def test_rpc0_8(init_starknet0_8, account_deployer):
    init_starknet0_8
    stark_privk = random.randint(1, 10**10)
    _, secp256r1_pubk = generate_secp256r1_keypair()
    withdrawal_limit_low = 121 * 10**6
    eth_fee_rate = 100 * 10**6
    stark_fee_rate = 100 * 10**6
    account_address, _ = await account_deployer(
        stark_privk=stark_privk,
        secp256r1_pubk=flatten_seq(secp256r1_pubk),
        multisig_thresh=0,
        withdrawal_limit_low=withdrawal_limit_low,
        eth_fee_rate=eth_fee_rate,
        stark_fee_rate=stark_fee_rate,
    )

    # Get account withdrawal limit low
    result = await call_contract_rpc(
        Call(
            to_addr=account_address,
            selector=get_selector_from_name("get_withdrawal_limit_low"),
            calldata=[],
        ), )
    print(f"Withdrawal limit low: {result[0]}")
    assert result[0] == withdrawal_limit_low

    transfer_call = Call(to_addr=STRK_CONTRACT,
                         selector=get_selector_from_name("transfer"),
                         calldata=[DEVNET_ACCOUNT_ADDRESS, 0, 0])

    high_resource_bounds = ResourceBoundsMapping(
        l1_gas=ResourceBounds(max_amount=int(1e6),
                              max_price_per_unit=int(100_000_000_000)),
        l1_data_gas=ResourceBounds(max_amount=int(1e6),
                                   max_price_per_unit=int(100_000_000_000)),
        l2_gas=ResourceBounds(max_amount=int(1e8),
                              max_price_per_unit=int(100_000_000_000)),
    )

    # Fails during validation because total gas fee is worth more
    # than the withdrawal limit low which means a strong signer is required
    with pytest.raises(Exception, match="INVALID_SIG"):
        await invoke_v3_direct_rpc(account_address=account_address,
                                   account_private_key=stark_privk,
                                   calls=[transfer_call],
                                   resource_bounds=high_resource_bounds)

    # Passes the validate state but fails during execution
    # specifically fails when trying to fetch balance of usdt for dwl bookkeeping
    # Spending should increase in this case
    low_resource_bounds = ResourceBoundsMapping(
        l1_gas=ResourceBounds(max_amount=int(1e6),
                              max_price_per_unit=int(100_000_000_000)),
        l1_data_gas=ResourceBounds(max_amount=int(1e6),
                                   max_price_per_unit=int(100_000_000_000)),
        l2_gas=ResourceBounds(max_amount=int(1e7),
                              max_price_per_unit=int(100_000_000_000)),
    )
    await invoke_v3_direct_rpc(account_address=account_address,
                               account_private_key=stark_privk,
                               calls=[transfer_call],
                               resource_bounds=low_resource_bounds)

    result = await call_contract_rpc(
        Call(
            to_addr=account_address,
            selector=get_selector_from_name("get_daily_spend"),
            calldata=[],
        ), )

    # spending should be the total overall fee of the resource bound
    assert (
        result[0] == ((low_resource_bounds.l1_data_gas.max_amount *
                       low_resource_bounds.l1_data_gas.max_price_per_unit +
                       low_resource_bounds.l2_gas.max_amount *
                       low_resource_bounds.l2_gas.max_price_per_unit +
                       low_resource_bounds.l1_gas.max_amount *
                       low_resource_bounds.l1_gas.max_price_per_unit) *
                      stark_fee_rate // 10**18) + 1
    ), "Daily spend should be equal to the sum of the max amounts of the resource bounds"
