import e2e.utils.utils_v2 as utils_v2
from e2e.utils.utils_v2 import TEST_HASH, MAX_EXECUTE_FEE_ETH, MAX_SIGN_FEE_ETH, MAX_EXECUTE_FEE_STRK, MAX_SIGN_FEE_STRK, TestSigner, check_pending_tx_event, STRK_ADDRESS, EXECUTION_RESOURCE_BOUNDS, SIGNER_RESOURCE_BOUNDS, HIGH_EXECUTION_RESOURCE_BOUNDS, HIGH_SIGNER_RESOURCE_BOUNDS, TestSigner
from e2e.utils.fixtures_moa import *
from e2e.utils.utils import cairo0_deployment_signer, create_legacy_stark_signer, execute_calls, get_contract_str

from collections import namedtuple
import pytest
import json
import random

from starknet_py.constants import FEE_CONTRACT_ADDRESS
from starknet_py.transaction_errors import (
    TransactionNotReceivedError,
    TransactionRevertedError,
)
from starknet_py.contract import Contract
from starknet_py.hash.selector import get_selector_from_name
from starknet_py.net.http_client import ClientError
from starknet_py.net.account.account import Account, KeyPair
from starknet_py.net.client_models import (
    Call,
    TransactionExecutionStatus,
)
from starknet_py.net.full_node_client import FullNodeClient
from starknet_py.hash.address import compute_address
from starknet_py.net.models.chains import StarknetChainId


@pytest.mark.asyncio
async def test_multicall_dapp_sanity(prepare_simple_signer):
    signer: TestSigner = prepare_simple_signer

    await signer.execute_calls([
        [
            signer.address, "assert_max_fee",
            [
                MAX_EXECUTE_FEE_ETH, MAX_EXECUTE_FEE_STRK, MAX_SIGN_FEE_ETH,
                MAX_SIGN_FEE_STRK
            ]
        ],
        [int(FEE_CONTRACT_ADDRESS, 16), "decimals", []],
        [int(FEE_CONTRACT_ADDRESS, 16), "totalSupply", []],
        [int(FEE_CONTRACT_ADDRESS, 16), "balanceOf", [signer.address]],
    ])


@pytest.mark.asyncio
async def test_external_entrypoint_guards(
    init_starknet,
    account_contracts_moa_str,
    account_deployer_moa,
):
    _, _, devnet_account = init_starknet

    account, _ = await account_deployer_moa([0], 0)

    (account_sierra_str, _, _, _) = account_contracts_moa_str
    abi = json.loads(account_sierra_str)["abi"]
    interfaces = [element for element in abi if element["type"] == "interface"]
    assert len(interfaces) > 0, "interface not found in abi"

    for interface in interfaces:
        for entry in interface["items"]:
            if (entry["name"] == "initializer"
                    or entry["name"].startswith("__validate")
                    or entry["type"] != "function"
                    or entry.get("state_mutability") == "view"):
                continue
            params_num = len(entry["inputs"])

            with pytest.raises((TransactionRevertedError, ClientError)):
                call = Call(
                    to_addr=account.address,
                    selector=get_selector_from_name(entry["name"]),
                    calldata=[0] * params_num,
                )
                tx2 = await devnet_account.execute_v1(
                    calls=call, max_fee=MAX_EXECUTE_FEE_ETH)
                await devnet_account.client.wait_for_tx(tx2.transaction_hash)


@pytest.mark.asyncio
async def test_is_valid_sig_sanity_stark_indexed(prepare_simple_signer):
    signer: TestSigner = prepare_simple_signer

    ((sig_r, sig_s), (preamble_r, preamble_s)) = signer.sign_hash(TEST_HASH)
    res = await signer.account.functions["is_valid_signature"].call(
        TEST_HASH,
        [
            0,
            signer.signers_info[0][0],
            signer.signers_info[0][1],
            preamble_r,
            preamble_s,
            2,
            sig_r,
            sig_s,
        ],
    )
    assert res[0] == utils_v2.VALID, "sig check failed"


@pytest.mark.asyncio
async def test_is_valid_sig_wrong_inner_sig(prepare_simple_signer):
    signer: TestSigner = prepare_simple_signer

    ((sig_r, sig_s), (preamble_r, preamble_s)) = signer.sign_hash(TEST_HASH)
    with pytest.raises(ClientError):
        await signer.account.functions["is_valid_signature"].call(
            TEST_HASH,
            [
                0,
                signer.signers_info[0][0],
                signer.signers_info[0][1],
                sig_r,  # Preamble expected (sig(poseidon(hash, ext sig)))
                sig_s,
                2,
                sig_r,
                sig_s,
            ],
        )


@pytest.mark.asyncio
async def test_is_valid_sig_wrong_external_sig(prepare_simple_signer):
    signer: TestSigner = prepare_simple_signer

    ((sig_r, sig_s), (preamble_r, preamble_s)) = signer.sign_hash(TEST_HASH)
    with pytest.raises(ClientError):
        await signer.account.functions["is_valid_signature"].call(
            TEST_HASH,
            [
                0,
                signer.signers_info[0][0],
                signer.signers_info[0][1],
                preamble_r,
                preamble_s,
                2,
                sig_r + 1,
                sig_s,
            ],
        )


@pytest.mark.asyncio
async def test_is_valid_sig_wrong_hash_stark_indexed(prepare_simple_signer):
    signer: TestSigner = prepare_simple_signer

    ((sig_r, sig_s), (preamble_r, preamble_s)) = signer.sign_hash(TEST_HASH)
    wrong_hash = TEST_HASH + 1
    with pytest.raises(ClientError):
        await signer.account.functions["is_valid_signature"].call(
            wrong_hash,
            [
                0,
                signer.signers_info[0][0],
                signer.signers_info[0][1],
                preamble_r,
                preamble_s,
                2,
                sig_r,
                sig_s,
            ],
        )


@pytest.mark.asyncio
async def test_is_valid_sig_2_sig_correct(prepare_signer):
    signer: TestSigner = await prepare_signer([0, 1], 2, [0, 1])

    ((sig_r, sig_s), (preamble_r, preamble_s)) = signer.sign_hash(TEST_HASH)
    ((sig_r_1, sig_s_1), (preamble_r_1,
                          preamble_s_1)) = signer.sign_hash(TEST_HASH, 1)
    res = await signer.account.functions["is_valid_signature"].call(
        TEST_HASH,
        [
            0,
            signer.signers_info[0][0],
            signer.signers_info[0][1],
            preamble_r,
            preamble_s,
            2,
            sig_r,
            sig_s,
            0,
            signer.signers_info[1][0],
            signer.signers_info[1][1],
            preamble_r_1,
            preamble_s_1,
            2,
            sig_r_1,
            sig_s_1,
        ],
    )
    assert res[0] == utils_v2.VALID, "sig check failed"


@pytest.mark.asyncio
async def test_is_valid_sig_2_sig_not_enough(prepare_signer):
    signer: TestSigner = await prepare_signer([0, 1], 2, [0, 1])

    ((sig_r, sig_s), (preamble_r, preamble_s)) = signer.sign_hash(TEST_HASH)

    with pytest.raises(ClientError,
                       match=encode_string_as_hex('NOT_ENOUGH_CONFIRMATIONS')):
        res = await signer.account.functions["is_valid_signature"].call(
            TEST_HASH,
            [
                0,
                signer.signers_info[0][0],
                signer.signers_info[0][1],
                preamble_r,
                preamble_s,
                2,
                sig_r,
                sig_s,
            ],
        )


@pytest.mark.asyncio
async def test_multisig_override_pending_txn(prepare_signer):
    signer: TestSigner = await prepare_signer([0, 1], 2, [0, 1])

    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)

    await signer.send_transactions(calls,
                                   signer_ids=[0],
                                   max_fee=MAX_SIGN_FEE_ETH)
    tx_hash = utils_v2.calculate_tx_hash(calls, signer.address,
                                         signer.get_guid(0), 1)
    await utils_v2.get_and_check_multisig_tx(signer.account, tx_hash, 1)

    await signer.send_transactions(calls,
                                   signer_ids=[0],
                                   max_fee=MAX_SIGN_FEE_ETH,
                                   pending_nonce=1)
    tx_hash2 = utils_v2.calculate_tx_hash(calls,
                                          signer.address,
                                          signer.get_guid(0),
                                          1,
                                          nonce=1)
    await utils_v2.get_and_check_multisig_tx(signer.account, tx_hash2, 1)

    assert tx_hash != tx_hash2, "pending transaction not replaced"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["signer_ids", "threshold"],
    [
        ([0], 0),
        ([0, 1], 0),
        ([0, 1], 2),
        ([1, 2], 2),
        ([0, 1, 2], 2),
        ([0, 1, 2], 3),
    ],
    ids=[
        "signers_1_threshold_0",
        "signers_2_threshold_0",
        "signers_2_threshold_2",
        "signers_2_threshold_2_reversed",
        "signers_3_threshold_2",
        "signers_3_threshold_3",
    ],
)
async def test_get_signers(prepare_signer, signer_ids, threshold):
    signer: TestSigner = await prepare_signer(signer_ids, threshold,
                                              signer_ids)

    res = await signer.account.functions["get_signers"].call()
    signer_list_res = res[0]['moa']
    assert len(signer_list_res) == len(signer_ids), "wrong signers number"
    for i in range(len(signer_ids)):
        assert signer.get_guid(i) in signer_list_res, "missing guid"


@pytest.mark.asyncio
async def test_add_external_signers(prepare_simple_signer):
    signer: TestSigner = prepare_simple_signer
    calldata = utils_v2.add_external_signers_calldata([1, 2], 2)

    _, res = await signer.execute_calls([
        [
            signer.address, "assert_max_fee",
            [
                MAX_EXECUTE_FEE_ETH, MAX_EXECUTE_FEE_STRK, MAX_SIGN_FEE_ETH,
                MAX_SIGN_FEE_STRK
            ]
        ],
        [signer.address, "add_external_signers", calldata],
    ])

    utils_v2.check_owner_added_event(res, ACCOUNTS[1].address,
                                     ACCOUNTS[1].pubk)
    utils_v2.check_owner_added_event(res, ACCOUNTS[2].address,
                                     ACCOUNTS[2].pubk)

    res = await signer.account.functions["get_signers"].call()
    signer_list_res = res[0]['moa']
    assert len(signer_list_res) == 3, "wrong signers number"

    res = await signer.account.functions["get_multisig_threshold"].call()
    assert res[0] == 2, "wrong threshold"


@pytest.mark.asyncio
async def test_declare_disabled(init_starknet, prepare_simple_signer):
    signer: TestSigner = prepare_simple_signer
    _, devnet_client, _ = init_starknet
    sierra_str, casm_str = get_contract_str(
        "target/dev/braavos_account_BraavosBaseAccount")

    with pytest.raises(ClientError,
                       match=encode_string_as_hex("NOT_IMPLEMENTED")):
        await utils_v2.declare(devnet_client, signer.get_account(0),
                               sierra_str, casm_str)


@pytest.mark.asyncio
async def test_add_same_external_signers_in_one_tx(prepare_simple_signer):
    signer: TestSigner = prepare_simple_signer
    calldata = utils_v2.add_external_signers_calldata([1, 1], 0)

    with pytest.raises((TransactionRevertedError, ClientError)):
        await signer.execute_calls([
            [
                signer.address, "assert_max_fee",
                [
                    MAX_EXECUTE_FEE_ETH, MAX_EXECUTE_FEE_STRK,
                    MAX_SIGN_FEE_ETH, MAX_SIGN_FEE_STRK
                ]
            ],
            [signer.address, "add_external_signers", calldata],
        ])


@pytest.mark.asyncio
async def test_add_same_external_signer_address_in_one_tx(
        prepare_simple_signer):
    signer: TestSigner = prepare_simple_signer
    calldata = [
        2,
        ACCOUNTS[0].address,
        ACCOUNTS[0].pubk,
        ACCOUNTS[0].address,
        ACCOUNTS[1].pubk,
        0,
    ]

    with pytest.raises((TransactionRevertedError, ClientError)):
        await signer.execute_calls([
            [
                signer.address, "assert_max_fee",
                [
                    MAX_EXECUTE_FEE_ETH, MAX_EXECUTE_FEE_STRK,
                    MAX_SIGN_FEE_ETH, MAX_SIGN_FEE_STRK
                ]
            ],
            [signer.address, "add_external_signers", calldata],
        ])


@pytest.mark.asyncio
async def test_add_same_external_signers_in_diff_tx(prepare_simple_signer):
    signer: TestSigner = prepare_simple_signer
    calldata = utils_v2.add_external_signers_calldata([1], 0)

    await signer.execute_calls([
        [
            signer.address, "assert_max_fee",
            [
                MAX_EXECUTE_FEE_ETH, MAX_EXECUTE_FEE_STRK, MAX_SIGN_FEE_ETH,
                MAX_SIGN_FEE_STRK
            ]
        ],
        [signer.address, "add_external_signers", calldata],
    ])

    res = await signer.account.functions["get_signers"].call()
    signer_list_res = res[0]['moa']
    assert len(signer_list_res) == 2, "wrong signers number"

    with pytest.raises((TransactionRevertedError, ClientError)):
        await signer.execute_calls([
            [
                signer.address, "assert_max_fee",
                [
                    MAX_EXECUTE_FEE_ETH, MAX_EXECUTE_FEE_STRK,
                    MAX_SIGN_FEE_ETH, MAX_SIGN_FEE_STRK
                ]
            ],
            [signer.address, "add_external_signers", calldata],
        ])


@pytest.mark.asyncio
async def test_try_add_empty_external_signers(prepare_simple_signer):
    signer: TestSigner = prepare_simple_signer
    with pytest.raises((TransactionRevertedError, ClientError)):
        await signer.execute_calls([
            [
                signer.address, "assert_max_fee",
                [
                    MAX_EXECUTE_FEE_ETH, MAX_EXECUTE_FEE_STRK,
                    MAX_SIGN_FEE_ETH, MAX_SIGN_FEE_STRK
                ]
            ],
            [signer.address, "add_external_signers", [1, 0, 0, 0]],
        ])


@pytest.mark.asyncio
async def test_empty_sig(prepare_simple_signer):
    signer: TestSigner = prepare_simple_signer
    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)

    with pytest.raises((TransactionNotReceivedError, ClientError)):
        await signer.send_transactions_custom_sig(calls)


@pytest.mark.asyncio
async def test_try_remove_all_signers(prepare_simple_signer):
    signer: TestSigner = prepare_simple_signer
    guid = signer.get_guid(0)
    with pytest.raises((TransactionRevertedError, ClientError)):
        await signer.execute_calls([
            [
                signer.address, "assert_max_fee",
                [
                    MAX_EXECUTE_FEE_ETH, MAX_EXECUTE_FEE_STRK,
                    MAX_SIGN_FEE_ETH, MAX_SIGN_FEE_STRK
                ]
            ],
            [signer.address, "remove_external_signers", [1, guid, 0]],
        ])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "remove_id",
        "threshold",
    ],
    [
        (0, 0),
        (1, 0),
    ],
    ids=[
        "signer_0_threshold_0",
        "signer_1_threshold_0",
    ],
)
async def test_remove_external_signers(prepare_signer, remove_id, threshold):
    signer: TestSigner = await prepare_signer([0, 1], 2, [0, 1])
    guid = signer.get_guid(remove_id)
    _, res = await signer.execute_calls(
        [
            [
                signer.address, "assert_max_fee",
                [
                    MAX_EXECUTE_FEE_ETH, MAX_EXECUTE_FEE_STRK,
                    MAX_SIGN_FEE_ETH, MAX_SIGN_FEE_STRK
                ]
            ],
            [signer.address, "remove_external_signers", [1, guid, threshold]],
        ],
        signer_ids=[0, 1],
    )
    utils_v2.check_owner_removed_event(res, *signer.signers_info[remove_id])

    valid_id = 1 - remove_id

    res = await signer.account.functions["get_signers"].call()
    signer_list_res = res[0]['moa']
    assert len(signer_list_res) == 1, "wrong signers number"
    assert signer_list_res[0] == signer.get_guid(valid_id), "wrong guid"

    res = await signer.account.functions["get_multisig_threshold"].call()
    assert res[0] == threshold, "wrong threshold"

    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)

    # removed signer no longer valid
    with pytest.raises((TransactionNotReceivedError, ClientError)):
        await signer.send_transactions(calls,
                                       signer_ids=[remove_id],
                                       proposer_id=remove_id,
                                       pending_nonce=1)

    # valid signer should be able to send transaction
    await signer.send_transactions(calls,
                                   signer_ids=[valid_id],
                                   proposer_id=valid_id,
                                   pending_nonce=1)


@pytest.mark.asyncio
async def test_invalid_threshold_after_remove_external_signers(prepare_signer):
    signer: TestSigner = await prepare_signer([0, 1], 2, [0, 1])
    guid = signer.get_guid(0)
    with pytest.raises((TransactionRevertedError, ClientError)):
        await signer.execute_calls(
            [
                [
                    signer.address, "assert_max_fee",
                    [
                        MAX_EXECUTE_FEE_ETH, MAX_EXECUTE_FEE_STRK,
                        MAX_SIGN_FEE_ETH, MAX_SIGN_FEE_STRK
                    ]
                ],
                [signer.address, "remove_external_signers", [1, guid, 2]],
            ],
            signer_ids=[0, 1],
        )


@pytest.mark.asyncio
async def test_removing_duplicate_signer_guids(prepare_signer):
    signer: TestSigner = await prepare_signer([0, 1, 2], 2, [0, 1, 2])
    guid = signer.get_guid(0)
    with pytest.raises((TransactionRevertedError, ClientError)):
        await signer.execute_calls(
            [
                [
                    signer.address, "assert_max_fee",
                    [
                        MAX_EXECUTE_FEE_ETH, MAX_EXECUTE_FEE_STRK,
                        MAX_SIGN_FEE_ETH, MAX_SIGN_FEE_STRK
                    ]
                ],
                [
                    signer.address, "remove_external_signers",
                    [2, guid, guid, 0]
                ],
            ],
            signer_ids=[0, 1],
        )


@pytest.mark.asyncio
async def test_removing_nonexistent_signer_guids(prepare_signer):
    signer: TestSigner = await prepare_signer([0, 1, 2], 2, [0, 1, 2])
    guid = signer.get_guid(0)
    with pytest.raises((TransactionRevertedError, ClientError)):
        await signer.execute_calls(
            [
                [
                    signer.address, "assert_max_fee",
                    [
                        MAX_EXECUTE_FEE_ETH, MAX_EXECUTE_FEE_STRK,
                        MAX_SIGN_FEE_ETH, MAX_SIGN_FEE_STRK
                    ]
                ],
                [
                    signer.address, "remove_external_signers",
                    [2, guid, 1231233, 0]
                ],
            ],
            signer_ids=[0, 1],
        )


@pytest.mark.asyncio
async def test_remove_and_add_external_signers(init_starknet,
                                               account_declare_moa,
                                               prepare_signer):
    _, _, signer_chash, signer_sierra_str = account_declare_moa
    _, _, devnet_account = init_starknet
    signer_abi = json.loads(signer_sierra_str)["abi"]

    signer: TestSigner = await prepare_signer([0, 1], 2, [0, 1])
    guid = signer.get_guid(0)
    _, res = await signer.execute_calls(
        [
            [
                signer.address, "assert_max_fee",
                [
                    MAX_EXECUTE_FEE_ETH, MAX_EXECUTE_FEE_STRK,
                    MAX_SIGN_FEE_ETH, MAX_SIGN_FEE_STRK
                ]
            ],
            [signer.address, "remove_external_signers", [1, guid, 0]],
        ],
        signer_ids=[0, 1],
    )

    utils_v2.check_owner_removed_event(res, *signer.signers_info[0])

    res = await signer.account.functions["get_multisig_threshold"].call()
    assert res[0] == 0, "wrong threshold after remove"

    ext_acc = await utils_v2.deploy_external_account(devnet_account,
                                                     signer_chash, signer_abi,
                                                     ACCOUNTS[2].pubk)
    _, res = await signer.execute_calls([
        [
            signer.address, "assert_max_fee",
            [
                MAX_EXECUTE_FEE_ETH, MAX_EXECUTE_FEE_STRK, MAX_SIGN_FEE_ETH,
                MAX_SIGN_FEE_STRK
            ]
        ],
        [signer.address, "add_external_signers", [1, *ext_acc, 2]],
    ],
                                        signer_ids=[1],
                                        proposer_id=1,
                                        pending_nonce=1)
    signer.signers_info.append(ext_acc)

    utils_v2.check_owner_added_event(res, *ext_acc)

    res = await signer.account.functions["get_multisig_threshold"].call()
    assert res[0] == 2, "wrong threshold after add"

    signer.signers.append(
        utils_v2.Account(
            address=signer.account.address,
            client=signer.client,
            key_pair=utils_v2.KeyPair.from_private_key(ACCOUNTS[2].pk),
            chain=DEVNET_CHAIN_ID,
        ))
    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)

    await signer.send_transactions(calls,
                                   signer_ids=[1, 2],
                                   proposer_id=1,
                                   pending_nonce=2)


@pytest.mark.asyncio
async def test_try_remove_deleted_signers(prepare_signer):
    signer: TestSigner = await prepare_signer([0, 1], 0, [0, 1])
    guid = signer.get_guid(1)
    calls = [
        [
            signer.address, "assert_max_fee",
            [
                MAX_EXECUTE_FEE_ETH, MAX_EXECUTE_FEE_STRK, MAX_SIGN_FEE_ETH,
                MAX_SIGN_FEE_STRK
            ]
        ],
        [signer.address, "remove_external_signers", [1, guid, 0]],
    ]
    await signer.execute_calls(calls)
    with pytest.raises((TransactionRevertedError, ClientError)):
        await signer.execute_calls(calls)


@pytest.mark.asyncio
async def test_account_with_50_signers_sign_in_1_tx(prepare_signer):
    total_signers = 50
    signer_ids = [0] * total_signers
    signer: TestSigner = await prepare_signer(signer_ids, total_signers,
                                              signer_ids)

    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)

    await signer.send_transactions(calls, signer_ids=range(total_signers))
    await utils_v2.get_and_check_multisig_tx(signer.account, 0, 0)


@pytest.mark.asyncio
async def test_account_with_50_signers_sign_in_2_tx_partial(prepare_signer):
    total_signers = 50
    signer_ids = [0] * total_signers
    signer: TestSigner = await prepare_signer(signer_ids, total_signers,
                                              signer_ids)

    calls = utils_v2.get_transfer_calls(signer.address, ACCOUNTS[0].address,
                                        10**8)

    await signer.send_transactions(calls,
                                   signer_ids=[0],
                                   max_fee=MAX_SIGN_FEE_ETH)
    tx_hash = utils_v2.calculate_tx_hash(calls, signer.address,
                                         signer.get_guid(0), 1)
    await utils_v2.get_and_check_multisig_tx(signer.account, tx_hash, 1)

    with pytest.raises((TransactionRevertedError, ClientError)):
        await signer.send_transaction(
            to=signer.address,
            selector_name="sign_pending_multisig_transaction",
            calldata=utils_v2.prepare_calldata(signer.get_guid(0), 0, calls),
            signer_ids=range(total_signers)[1:49],
            max_fee=MAX_SIGN_FEE_ETH,
            pending_calls=calls,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "sierra_path",
        "casm_path",
        "src6_supported",
    ],
    [
        [
            "./e2e/contracts/upgrade_test_moa.sierra.json",
            "./e2e/contracts/upgrade_test_moa.casm.json",
            True,
        ],
        [
            "./e2e/contracts/upgrade_test_fail_src6.sierra.json",
            "./e2e/contracts/upgrade_test_fail_src6.casm.json",
            False,
        ],
    ],
    ids=[
        "src6_supported",
        "src6_not_supported",
    ],
)
async def test_upgrade(init_starknet, prepare_simple_signer, sierra_path,
                       casm_path, src6_supported):
    _, devnet_client, devnet_account = init_starknet
    signer = prepare_simple_signer
    with open(sierra_path, "r") as f:
        sierra_content = f.read()
    with open(casm_path, "r") as f:
        casm_content = f.read()
    upgradable_hash = await utils_v2.declare(
        devnet_client,
        devnet_account,
        sierra_content,
        casm_content,
    )
    try:
        await signer.execute_calls([
            [
                signer.address, "assert_max_fee",
                [
                    MAX_EXECUTE_FEE_ETH, MAX_EXECUTE_FEE_STRK,
                    MAX_SIGN_FEE_ETH, MAX_SIGN_FEE_STRK
                ]
            ],
            [signer.address, "upgrade", [upgradable_hash]],
        ])
    except (TransactionRevertedError, ClientError):
        assert not src6_supported, "Failed upgrade with valid interface"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    [
        "num_signers",
        "num_multisig",
        "deleted_cairo0_signers",
        "check_storage_migrate_reentrancy",
    ],
    [
        (4, 2, [], True),
        (6, 3, [1, 2, 6], False),
    ],
    ids=[
        "4_of_2_non_deleted",
        "6_of_3_deleted_1_2_6",
    ],
)
async def test_regenesis_upgrade(
    init_starknet,
    account_declare_moa,
    num_signers,
    num_multisig,
    deleted_cairo0_signers,
    check_storage_migrate_reentrancy,
):
    devnet_url, devnet_client, devnet_account = init_starknet
    devnet_client: FullNodeClient
    devnet_account: Account
    account_moa_chash, _, _, _ = account_declare_moa

    account_cairo0_moa_chash = await utils_v2.declare_v0(
        devnet_client, devnet_account, "e2e/contracts/account_cairo0_moa.json")
    account_cairo0_chash = await utils_v2.declare_v0(
        devnet_client, devnet_account, "e2e/contracts/account_cairo0.json")
    proxy_cairo0_chash = await utils_v2.declare_v0(
        devnet_client, devnet_account, "e2e/contracts/proxy_cairo0.json")

    cairo0_owners = []
    cairo0_moa_account = None
    for i in range(
            num_signers +
            1):  # the last created account will be the MOA cairo0 account
        stark_privk = random.randint(1, 10**10)
        stark_keypair = KeyPair.from_private_key(stark_privk)
        stark_pubk = stark_keypair.public_key
        ctor_calldata = [
            account_cairo0_moa_chash
            if i == num_signers else account_cairo0_chash,
            get_selector_from_name("initializer"), 1, stark_pubk
        ]
        account_address = compute_address(
            class_hash=proxy_cairo0_chash,
            salt=stark_pubk,
            constructor_calldata=ctor_calldata,
        )
        exec = await devnet_account.execute_v1(
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
            "_DeploySigner", ["sign_transaction"
                              ])(lambda depl_account: cairo0_deployment_signer(
                                  depl_account, account_address, stark_keypair,
                                  account_cairo0_chash, [0] * 7))
        deployer_account = Account(
            client=devnet_client,
            address=account_address,
            signer=deploy_signer,
        )
        signed_account_depl = await deployer_account.sign_deploy_account_v1(
            class_hash=proxy_cairo0_chash,
            contract_address_salt=stark_pubk,
            constructor_calldata=ctor_calldata,
            auto_estimate=True,
        )
        account_depl = await devnet_client.deploy_account(signed_account_depl)
        receipt = await devnet_client.wait_for_tx(account_depl.transaction_hash
                                                  )
        assert receipt.execution_status == TransactionExecutionStatus.SUCCEEDED
        account = Account(
            client=devnet_client,
            address=account_address,
            key_pair=KeyPair.from_private_key(stark_privk),
            chain=DEVNET_CHAIN_ID,
        )
        await account.cairo_version
        if i == num_signers:
            cairo0_moa_account = account
        else:
            owner_id = i + 1
            cairo0_owners.append((owner_id, account, owner_id
                                  in deleted_cairo0_signers))

    _ = await execute_calls(
        cairo0_moa_account,
        Call(
            to_addr=cairo0_moa_account.address,
            selector=get_selector_from_name('add_external_account_signers'),
            calldata=[
                len(cairo0_owners),
                *[a.address for (_, a, _) in cairo0_owners], num_multisig
            ],
        ))

    # We already treat the removed owners as removed - test setup should leave enough non-removed
    # owners to meet the num_multisig threshold
    def _cairo0_moa_signer(txn: AccountTransaction):
        sig = []
        preamble_set = False
        num_signers = 0
        for owner_id, owner_account, is_deleted in cairo0_owners:
            if is_deleted:
                continue
            owner_sig = owner_account.signer.sign_transaction(txn)
            if not preamble_set:
                sig += [owner_id, *owner_sig, owner_id, 3, 0, *owner_sig]
                preamble_set = True
            else:
                sig += [owner_id, 3, 0, *owner_sig]
            num_signers += 1
            if num_signers == num_multisig:
                break
        return sig

    cairo0_moa_account.signer = namedtuple(
        "c0_moa_signer",
        "sign_transaction")(lambda txn: _cairo0_moa_signer(txn))

    if len(deleted_cairo0_signers) != 0:
        _ = await execute_calls(
            cairo0_moa_account,
            Call(
                to_addr=cairo0_moa_account.address,
                selector=get_selector_from_name(
                    'remove_external_account_signers'),
                calldata=[
                    len(deleted_cairo0_signers), *deleted_cairo0_signers,
                    num_multisig
                ],
            ))

    await execute_calls(
        cairo0_moa_account,
        Call(
            to_addr=cairo0_moa_account.address,
            selector=get_selector_from_name("upgrade_regenesis"),
            calldata=[
                account_moa_chash,
                0x2ceccef7f994940b3962a6c67e0ba4fcd37df7d131417c604f91e03caecc1cd
            ],
        ),
    )

    assert await devnet_client.get_class_hash_at(
        cairo0_moa_account.address
    ) == account_moa_chash, 'expected Cairo 2 MOA class hash'

    moa_account = cairo0_moa_account
    moa_account._cairo_version = 1

    signers_after_migrate = await devnet_client.call_contract(
        Call(
            to_addr=moa_account.address,
            selector=get_selector_from_name('get_signers'),
            calldata=[],
        ))
    for owner_id, owner, is_deleted in cairo0_owners:
        guid = poseidon_hash_many(
            [owner.address, owner.signer.key_pair.public_key])
        should_exist = not is_deleted
        assert (
            guid in signers_after_migrate
        ) == should_exist, f'incorrect migration of guid {owner_id, guid, is_deleted}'

    def _cairo2_moa_signer(calls, nonce):
        txn_hash = None
        sig = []
        num_signers = 0
        for owner_id, owner_account, is_deleted in cairo0_owners:
            if is_deleted:
                continue
            if txn_hash is None:
                proposer_guid = poseidon_hash_many([
                    owner_account.address,
                    owner_account.signer.key_pair.public_key
                ])
                txn_hash = utils_v2.calculate_tx_hash(
                    calls=calls,
                    account_address=moa_account.address,
                    guid=proposer_guid,
                    signers_len=num_multisig,
                    nonce=nonce,
                )

            owner_sig = message_signature(
                txn_hash, owner_account.signer.key_pair.private_key)
            preamble_hash = utils_v2.calculate_preamble_hash(
                moa_account.address, txn_hash, list(owner_sig))
            owner_preamble = message_signature(
                preamble_hash, owner_account.signer.key_pair.private_key)
            sig += [
                0, owner_account.address, owner_account.signer.public_key,
                *owner_preamble, 2, *owner_sig
            ]
            num_signers += 1
            if num_signers == num_multisig:
                break
        return sig

    balance_of_calls = [
        Call(
            to_addr=moa_account.address,
            selector=get_selector_from_name("assert_max_fee"),
            calldata=[
                MAX_EXECUTE_FEE_ETH, MAX_EXECUTE_FEE_STRK, MAX_SIGN_FEE_ETH,
                MAX_SIGN_FEE_STRK
            ],
        ),
        Call(
            to_addr=int(FEE_CONTRACT_ADDRESS, 16),
            selector=get_selector_from_name("balanceOf"),
            calldata=[moa_account.address],
        )
    ]
    moa_nonce = await moa_account.get_nonce()
    moa_account.signer = namedtuple("c2_moa_signer", "sign_transaction")(
        lambda txn: _cairo2_moa_signer(balance_of_calls, moa_nonce))

    # Check signing sanity
    _ = await execute_calls(moa_account, balance_of_calls)

    if check_storage_migrate_reentrancy:
        # Fail on regenesis storage migration re-entry
        migrate_storage_calls = [
            Call(
                to_addr=moa_account.address,
                selector=get_selector_from_name("assert_max_fee"),
                calldata=[
                    MAX_EXECUTE_FEE_ETH, MAX_EXECUTE_FEE_STRK,
                    MAX_SIGN_FEE_ETH, MAX_SIGN_FEE_STRK
                ],
            ),
            Call(
                to_addr=account.address,
                selector=get_selector_from_name('migrate_storage'),
                calldata=[int.from_bytes(b'000.000.011', 'big')],
            ),
        ]
        moa_nonce = await moa_account.get_nonce()
        moa_account.signer = namedtuple("c2_moa_signer", "sign_transaction")(
            lambda txn: _cairo2_moa_signer(migrate_storage_calls, moa_nonce))
        with pytest.raises(Exception, match="INVALID_STORAGE_MIGRATE"):
            await execute_calls(moa_account, migrate_storage_calls)
