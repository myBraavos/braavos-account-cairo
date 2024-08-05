import e2e.utils.utils as utils_v1

import time
import requests
from typing import Dict, List
from pathlib import Path
from collections import namedtuple
from poseidon_py.poseidon_hash import poseidon_hash_many
import dataclasses

from starknet_py.constants import FEE_CONTRACT_ADDRESS, QUERY_VERSION_BASE
from starknet_py.hash.selector import get_selector_from_name
from starknet_py.net.account.account import (
    Account,
    KeyPair,
)
from starknet_py.hash.utils import message_signature
from starknet_py.hash.casm_class_hash import compute_casm_class_hash
from starknet_py.hash.sierra_class_hash import compute_sierra_class_hash
from starknet_py.hash.class_hash import compute_class_hash
from starknet_py.hash.transaction import TransactionHashPrefix
from starknet_py.net.models.chains import StarknetChainId
from starknet_py.utils.iterable import ensure_iterable
from starknet_py.contract import Contract
from starknet_py.net.client_models import (Call, ResourceBounds)
from starknet_py.net.schemas.rpc.contract import (
    CasmClassSchema,
    ContractClassSchema,
    SierraCompiledContractSchema,
)
from starknet_py.net.account.account import _parse_calls
from starknet_py.net.full_node_client import FullNodeClient
from e2e.utils.typed_data import get_typed_data
from starknet_py.net.client_errors import ClientError


class AccountDetails:

    def __init__(self, address, pk, pubk):
        self.address = address
        self.pk = pk
        self.pubk = pubk


VALID = 0x56414C4944
NOT_ENOUGH_CONFIRMATIONS = 0x4E4F545F454E4F5547485F434F4E4649524D4154494F4E53
TEST_HASH = 0x66EE969C4DC7E5296BF9B469A2ED0591EA065A7EB96F596B958F792AAA6831E

MAX_EXECUTE_FEE_ETH = 5 * 10**17
MAX_SIGN_FEE_ETH = 3 * 10**16

MAX_EXECUTE_FEE_STRK = 5 * 10**18
MAX_SIGN_FEE_STRK = 3 * 10**17

EXECUTION_RESOURCE_BOUNDS = ResourceBounds(max_price_per_unit=500 * 10**9,
                                           max_amount=10**7)
SIGNER_RESOURCE_BOUNDS = ResourceBounds(max_price_per_unit=300 * 10**9,
                                        max_amount=10**6)

HIGH_EXECUTION_RESOURCE_BOUNDS = ResourceBounds(max_price_per_unit=1 +
                                                500 * 10**9,
                                                max_amount=10**7)
HIGH_SIGNER_RESOURCE_BOUNDS = ResourceBounds(max_price_per_unit=1 +
                                             300 * 10**9,
                                             max_amount=10**6)

# STANDARD_RESOURCE_BOUNDS = ResourceBounds(max_price_per_unit=100 * 10**9, max_amount=10**6)
# EXECUTION_RESOURCE_BOUNDS = ResourceBounds(max_price_per_unit=500 * 10**9, max_amount=10**6)
# HIGH_SIGNER_RESOURCE_BOUNDS = ResourceBounds(max_price_per_unit=110 * 10**9, max_amount=10**6)
# HIGH_EXECUTION_RESOURCE_BOUNDS = ResourceBounds(max_price_per_unit=600 * 10**9, max_amount=10**7)

STRK_ADDRESS = 0x04718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D

# starknet-devnet-rs seed 0
ACCOUNTS = [
    AccountDetails(
        0x64B48806902A367C8598F4F95C305E8C1A1ACBA5F082D294A43793113115691,
        0x71D7BB07B9A64F6F78AC4C816AFF4DA9,
        0x39D9E6CE352AD4530A0EF5D5A18FD3303C3606A7FA6AC5B620020AD681CC33B,
    ),
    AccountDetails(
        0x78662E7352D062084B0010068B99288486C2D8B914F6E2A55CE945F8792C8B1,
        0xE1406455B7D66B1690803BE066CBE5E,
        0x7A1BB2744A7DD29BFFD44341DBD78008ADB4BC11733601E7EDDFF322ADA9CB,
    ),
    AccountDetails(
        0x49DFB8CE986E21D354AC93EA65E6A11F639C1934EA253E5FF14CA62ECA0F38E,
        0xA20A02F0AC53692D144B20CB371A60D7,
        0xB8FD4DDD415902D96F61B7AD201022D495997C2DFF8EB9E0EB86253E30FABC,
    ),
    AccountDetails(
        0x4F348398F859A55A0C80B1446C5FDC37EDB3A8478A32F10764659FC241027D3,
        0xA641611C17D4D92BD0790074E34BEEB7,
        0x5E05D2510C6110BDE03DF9C1C126A1F592207D78CD9E481AC98540D5336D23C,
    ),
]
# katana
# ACCOUNTS = [
#     AccountDetails(
#         0x517ECECD29116499F4A1B64B094DA79BA08DFD54A3EDAA316134C41F8160973,
#         0x1800000000300000180000000000030000000000003006001800006600,
#         0x2B191C2F3ECF685A91AF7CF72A43E7B90E2E41220175DE5C4F7498981B10053,
#     ),
#     AccountDetails(
#         0x5686A647A9CDD63ADE617E0BAF3B364856B813B508F03903EB58A7E622D5855,
#         0x33003003001800009900180300D206308B0070DB00121318D17B5E6262150B,
#         0x4C0F884B8E5B4F00D97A3AAD26B2E5DE0C0C76A555060C837DA2E287403C01D,
#     ),
#     AccountDetails(
#         0x765149D6BC63271DF7B0316537888B81AA021523F9516A05306F10FD36914DA,
#         0x1C9053C053EDF324AEC366A34C6901B1095B07AF69495BFFEC7D7FE21EFFB1B,
#         0x4C339F18B9D1B95B64A6D378ABD1480B2E0D5D5BD33CD0828CBCE4D65C27284,
#     ),
#     AccountDetails(
#         0x586364C42CF7F6C968172BA0806B7403C567544266821C8CD28C292A08B2346,
#         0x2BBF4F9FD0BBB2E60B0316C1FE0B76CF7A4D0198BD493CED9B8DF2A3A24D68A,
#         0x640466EBD2CE505209D3E5C4494B4276ED8F1CDE764D757EB48831961F7CDEA,
#     ),
# ]


def get_test_contract_path(contract_name: str, contract_type: str):
    return Path(f"e2e/contracts/{contract_name}.{contract_type}.json")


def load_test_contract(contract_name: str):
    sierra_path = get_test_contract_path(contract_name, "sierra")
    with open(sierra_path, "r") as f:
        sierra_content = f.read()
    casm_path = get_test_contract_path(contract_name, "casm")
    with open(casm_path, "r") as f:
        casm_content = f.read()
    return sierra_content, casm_content


async def transfer_eth(from_acc, to_acc, amount, client):
    exec = await from_acc.execute_v1(
        Call(
            to_addr=int(FEE_CONTRACT_ADDRESS, 16),
            selector=get_selector_from_name("transfer"),
            calldata=[
                to_acc.address,
                amount,
                0,
            ],
        ),
        max_fee=int(0.1 * 10**18),
    )
    await client.wait_for_tx(exec.transaction_hash)


async def transfer_strk(from_acc, to_acc, amount, client):
    exec = await from_acc.execute_v1(
        Call(
            to_addr=STRK_ADDRESS,
            selector=get_selector_from_name("transfer"),
            calldata=[
                to_acc.address,
                amount,
                0,
            ],
        ),
        max_fee=int(0.1 * 10**18),
    )
    await client.wait_for_tx(exec.transaction_hash)


class TestSigner:
    __test__ = False

    def __init__(self, devnet_client, account, signers_pk, signers_info):
        self.account: Contract = account
        self.address = account.address
        self.client: FullNodeClient = devnet_client
        self.signers: List[Account] = []
        self.signers_info = signers_info
        for pk in signers_pk:
            signer = Account(
                address=account.address,
                client=devnet_client,
                key_pair=KeyPair.from_private_key(pk),
                chain=utils_v1.DEVNET_CHAIN_ID,
            )
            self.signers.append(signer)

    def get_account(self, id):
        return self.signers[id]

    def get_guid(self, id):
        return poseidon_hash_many(self.signers_info[id])

    async def send_transaction(
        self,
        to,
        selector_name,
        calldata,
        nonce=None,
        max_fee=MAX_EXECUTE_FEE_ETH,
        signer_ids=[0],
        is_v3=False,
        l1_resource_bounds=EXECUTION_RESOURCE_BOUNDS,
        proposer_id=0,
        pending_nonce=0,
        pending_calls=None,
    ):
        return await self.send_transactions(
            [Call(to, get_selector_from_name(selector_name), calldata)],
            nonce,
            max_fee,
            signer_ids,
            is_v3=is_v3,
            l1_resource_bounds=l1_resource_bounds,
            proposer_id=proposer_id,
            pending_nonce=pending_nonce,
            pending_calls=pending_calls)

    async def estimate_fee(
        self,
        to,
        selector_name,
        calldata,
        nonce=None,
        signer_ids=[0],
        is_v3=False,
        l1_resource_bounds=EXECUTION_RESOURCE_BOUNDS,
    ):
        return await self.estimate_fees(
            [Call(to, get_selector_from_name(selector_name), calldata)],
            nonce,
            signer_ids,
            is_v3=is_v3,
            l1_resource_bounds=l1_resource_bounds)

    async def send_transactions(
        self,
        calls,
        nonce=None,
        max_fee=MAX_EXECUTE_FEE_ETH,
        signer_ids=[0],
        is_v3=False,
        l1_resource_bounds=EXECUTION_RESOURCE_BOUNDS,
        proposer_id=0,
        pending_nonce=0,
        pending_calls=None,
    ):
        invoke = await self.prepare_invoke(calls,
                                           nonce,
                                           max_fee,
                                           signer_ids,
                                           is_v3,
                                           l1_resource_bounds,
                                           proposer_id,
                                           pending_nonce,
                                           pending_calls=pending_calls)

        tx = await self.client.send_transaction(invoke)
        res = await self.client.wait_for_tx(tx.transaction_hash)
        return (tx.transaction_hash, res)

    async def estimate_fees(
        self,
        calls,
        nonce=None,
        signer_ids=[0],
        is_v3=False,
        l1_resource_bounds=EXECUTION_RESOURCE_BOUNDS,
    ):
        invoke = await self.prepare_invoke(calls, nonce, 0, signer_ids, is_v3,
                                           l1_resource_bounds)
        invoke = dataclasses.replace(invoke,
                                     version=invoke.version +
                                     QUERY_VERSION_BASE)
        return await self.client.estimate_fee(invoke)

    async def prepare_invoke(self,
                             calls,
                             nonce,
                             max_fee,
                             signer_ids,
                             is_v3,
                             l1_resource_bounds,
                             proposer_id=0,
                             pending_nonce=0,
                             pending_calls=None):
        if is_v3:
            invoke = await self.signers[signer_ids[0]]._prepare_invoke_v3(
                calls, nonce=nonce, l1_resource_bounds=l1_resource_bounds)
        else:
            invoke = await self.signers[signer_ids[0]]._prepare_invoke(
                calls,
                nonce=nonce,
                max_fee=max_fee,
            )
        tx_hash = calculate_tx_hash(
            calls if pending_calls is None else pending_calls,
            self.address,
            self.get_guid(proposer_id),
            len(signer_ids),
            nonce=pending_nonce)
        for id in signer_ids:
            r, s = message_signature(
                msg_hash=tx_hash, priv_key=self.signers[id].signer.private_key)
            preamble_hash = calculate_preamble_hash(self.address, tx_hash,
                                                    [r, s])
            preamble_r, preamble_s = message_signature(
                msg_hash=preamble_hash,
                priv_key=self.signers[id].signer.private_key)
            invoke.signature.append(0)  # signature_type
            invoke.signature.append(self.signers_info[id][0])
            invoke.signature.append(self.signers_info[id][1])
            invoke.signature.append(preamble_r)
            invoke.signature.append(preamble_s)
            invoke.signature.append(2)
            invoke.signature.append(r)
            invoke.signature.append(s)
        return invoke

    async def send_transactions_custom_sig(self,
                                           calls,
                                           nonce=None,
                                           max_fee=MAX_EXECUTE_FEE_ETH,
                                           sig=[]):
        invoke = await self.signers[0]._prepare_invoke(calls=calls,
                                                       nonce=nonce,
                                                       max_fee=max_fee)
        invoke.signature.extend(sig)

        tx = await self.client.send_transaction(invoke)
        res = await self.client.wait_for_tx(tx.transaction_hash)
        return (tx.transaction_hash, res)

    async def execute_calls(self,
                            calls,
                            nonce=None,
                            max_fee=MAX_EXECUTE_FEE_ETH,
                            signer_ids=[0],
                            proposer_id=0,
                            pending_nonce=0):
        parsed_calls = [
            Call(call[0], get_selector_from_name(call[1]), call[2])
            for call in calls
        ]
        return await self.send_transactions(calls=parsed_calls,
                                            nonce=nonce,
                                            max_fee=max_fee,
                                            signer_ids=signer_ids,
                                            proposer_id=proposer_id,
                                            pending_nonce=pending_nonce)

    def sign_hash(self, hash, acc_id=0, signer=None):
        txn_r, txn_s = message_signature(
            hash,
            self.get_account(acc_id).signer.key_pair.private_key,
        )
        preamble_hash = calculate_preamble_hash(
            self.get_account(acc_id).address, hash, [txn_r, txn_s])
        preamble_r, preamble_s = message_signature(
            preamble_hash,
            self.get_account(acc_id).signer.key_pair.private_key,
        )

        return (
            (txn_r, txn_s),
            (preamble_r, preamble_s),
        )


async def declare(devnet_client: FullNodeClient, devnet_account: Account,
                  sierra_str, casm_str):
    chash = compute_casm_class_hash(CasmClassSchema().loads(casm_str))
    sierra_chash = compute_sierra_class_hash(
        SierraCompiledContractSchema().loads(sierra_str, unknown="exclude"))
    declare_signed_txn = await devnet_account.sign_declare_v2(
        compiled_contract=sierra_str,
        compiled_class_hash=chash,
        max_fee=int(10**18),
    )
    account_decl = await devnet_client.declare(declare_signed_txn)
    await devnet_client.wait_for_tx(account_decl.transaction_hash)
    return sierra_chash


async def declare_v0(devnet_client, devnet_account, contract_path):
    with open(contract_path, mode="r", encoding="utf8") as compiled_contract:

        compiled_contract_content = compiled_contract.read()
        cairo0_chash = compute_class_hash(ContractClassSchema().loads(
            compiled_contract_content, unknown="exclude"))

        class_exists = True
        try:
            await devnet_account.client.get_class_by_hash(cairo0_chash)
        except ClientError:
            class_exists = False

        if not class_exists:

            declare_tx = await devnet_account.sign_declare_v1(
                compiled_contract=compiled_contract_content,
                max_fee=int(0.1 * 10**18),
            )

            decl = await devnet_client.declare(transaction=declare_tx)
            await devnet_client.wait_for_tx(decl.transaction_hash)

        return cairo0_chash


def get_transfer_calls(account_addr,
                       to_addr,
                       transfer_amount,
                       max_fee_eth=MAX_EXECUTE_FEE_ETH,
                       signer_max_fee_eth=MAX_SIGN_FEE_ETH,
                       max_fee_stark=MAX_EXECUTE_FEE_STRK,
                       signer_max_fee_stark=MAX_SIGN_FEE_STRK,
                       is_v3=False):
    calldata = [
        to_addr,
        transfer_amount,
        0,
    ]
    assert_max_fee_calldata = []
    if not max_fee_eth is None:
        assert_max_fee_calldata.append(max_fee_eth)
    if not max_fee_stark is None:
        assert_max_fee_calldata.append(max_fee_stark)
    if not signer_max_fee_eth is None:
        assert_max_fee_calldata.append(signer_max_fee_eth)
    if not signer_max_fee_stark is None:
        assert_max_fee_calldata.append(signer_max_fee_stark)

    calls = [
        Call(account_addr, get_selector_from_name("assert_max_fee"),
             assert_max_fee_calldata),
        Call(STRK_ADDRESS if is_v3 else int(FEE_CONTRACT_ADDRESS, 16),
             get_selector_from_name("transfer"), calldata),
    ]
    return calls


def serialize_calls(calls):
    return _parse_calls(1, calls)


def prepare_calldata(guid, nonce, calls):
    return [guid, nonce, *serialize_calls(calls)]


async def get_and_check_multisig_tx(account, tx, confirmations):
    res = await account.functions["get_pending_multisig_transaction"].call()
    assert res[0]["pending_tx_hash"] == tx, "wrong tx"
    assert res[0]["confirmations"] == confirmations, "wrong confirmations"


async def get_and_check_multisig_tx_ex(account, tx, is_executed,
                                       confirmations):
    if is_executed:
        return await get_and_check_multisig_tx(account, 0, 0)
    return await get_and_check_multisig_tx(account, tx, confirmations)


def add_external_signers_calldata(signer_ids, threshold):
    calldata = [len(signer_ids)]
    for i in signer_ids:
        calldata.append(ACCOUNTS[i].address)
        calldata.append(ACCOUNTS[i].pubk)
    calldata.append(threshold)
    return calldata


def check_pending_tx_event(tx_res,
                           tx_hash,
                           sig_num,
                           is_executed,
                           should_emit_event=True):
    event_key = 0x2614462AA39A5F4DBC8CD316E773D7EAF705E22206EE80944B24B1B708D6DCD
    for event in tx_res.events:
        if event.keys[0] == event_key:
            assert should_emit_event, "Unexpected event present"
            assert event.keys[1] == tx_hash, "Wrong event tx_hash"
            assert event.data[0] == sig_num, "Wrong event sig_num"
            assert (event.data[1 + event.data[0]] == is_executed
                    ), "Wrong event is_executed"
            return

    assert not should_emit_event, "Event not found"


def check_owner_added_event(receipt, address, pubkey):
    assert utils_v1.txn_receipt_contains_event(
        receipt,
        [
            get_selector_from_name("OwnerAdded"),
            poseidon_hash_many([address, pubkey])
        ],
        [utils_v1.MOA_SIGNER_TYPE],
    ), "no event emitted for added owner"


def check_owner_removed_event(receipt, address, pubkey):
    assert utils_v1.txn_receipt_contains_event(
        receipt,
        [
            get_selector_from_name("OwnerRemoved"),
            poseidon_hash_many([address, pubkey])
        ],
        [utils_v1.MOA_SIGNER_TYPE],
    ), "no event emitted for removed owner"


async def deploy_external_account(devnet_account, signer_chash, signer_abi,
                                  pubk):
    deploy_result = await Contract.deploy_contract_v1(
        account=devnet_account,
        class_hash=signer_chash,
        abi=signer_abi,
        constructor_args={"pub_key": pubk},
        max_fee=int(1e18),
        cairo_version=1,
    )

    await devnet_account.client.wait_for_tx(deploy_result.hash)
    return (deploy_result.deployed_contract.address, pubk)


def txn_stub(tx_hash: int):

    def calc_hash(chain_id: int):
        return tx_hash

    return namedtuple("AccountTransaction",
                      ["calculate_hash"])(lambda txn: calc_hash(txn))


def calculate_preamble_hash(account_address, txn_hash, ext_sig):
    typed_data = get_typed_data(
        {
            "Moa Transaction Hash": txn_hash,
            "External Signature": ext_sig,
        }, {
            "MOASignaturePreambleHash": [
                {
                    "name": "Moa Transaction Hash",
                    "type": "felt",
                },
                {
                    "name": "External Signature",
                    "type": "felt*",
                },
            ],
        }, "MOASignaturePreambleHash", "MOA.signature_preamble_hash", "1")

    return typed_data.message_hash(account_address)


def calculate_tx_hash(calls, account_address, guid, signers_len, nonce=0):
    typed_data = get_typed_data(
        {
            "Proposer Guid": guid,
            "Nonce": nonce,
            "Calls": utils_v1.parse_calls_for_typed_data(
                ensure_iterable(calls)),
            "Num Signers": signers_len,
        }, {
            "MOATransaction": [
                {
                    "name": "Proposer Guid",
                    "type": "felt"
                },
                {
                    "name": "Nonce",
                    "type": "felt"
                },
                {
                    "name": "Calls",
                    "type": "Call*"
                },
                {
                    "name": "Num Signers",
                    "type": "u128",
                },
            ],
            "Call": [
                {
                    "name": "To",
                    "type": "ContractAddress"
                },
                {
                    "name": "Selector",
                    "type": "selector"
                },
                {
                    "name": "Calldata",
                    "type": "felt*"
                },
            ],
        }, "MOATransaction", "MOA.transaction_hash", "1")
    return typed_data.message_hash(account_address)


def get_max_resource_bounds(is_executing):
    return EXECUTION_RESOURCE_BOUNDS if is_executing else SIGNER_RESOURCE_BOUNDS


def get_max_fee(is_executing):
    return MAX_EXECUTE_FEE_ETH if is_executing else MAX_SIGN_FEE_ETH


def increase_devnet_days(devnet_url, days):
    requests.post(f"{devnet_url}/increase_time",
                  json={"time": days * 24 * 60 * 60})


async def validate_tx_limit(signer, id, expected_limit, days=0):
    guid = signer.get_guid(id)
    res = await signer.account.functions["get_tx_count"].call(
        guid, int(time.time() / 86400 + days))
    assert res[0] == expected_limit, "invalid tx limit"
