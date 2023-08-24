import asyncio
from collections import namedtuple
import pytest
import pytest_asyncio
from starkware.cairo.lang.vm.crypto import pedersen_hash
from starkware.starknet.business_logic.state.state import BlockInfo
from starkware.starknet.business_logic.transaction.objects import InternalDeclare
from starkware.starknet.core.os.contract_class.deprecated_class_hash import compute_deprecated_class_hash
from starkware.starknet.definitions.general_config import StarknetChainId
from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.testing.starknet import StarknetContract
from starkware.starknet.compiler.compile import get_selector_from_name

from utils import (
    TestSigner,
    assert_revert,
    assert_event_emitted,
    assert_event_emitted_in_call_info,
    deploy_account_txn,
    get_contract_def,
    parse_get_signers_response,
    to_uint,
    send_raw_invoke,
    str_to_felt,
    TestECCSigner,
    flatten_seq,
)

IACCOUNT_ID = 0xF10DBD44

signer = TestSigner(123456789987654321)


@pytest.fixture(scope="module")
def event_loop():
    return asyncio.get_event_loop()


@pytest.fixture(scope="module")
def contract_defs():
    proxy_def = get_contract_def("lib/openzeppelin/upgrades/Proxy.cairo")
    account_def = get_contract_def("account/Account.cairo")
    account_base_impl_def = get_contract_def("account/AccountBaseImpl.cairo")
    erc20_def = get_contract_def("tests/aux/ERC20_Flattened.cairo")

    return proxy_def, account_def, erc20_def, account_base_impl_def


@pytest_asyncio.fixture(scope="module")
async def init_module_scoped_starknet():
    starknet = await Starknet.empty()
    return starknet


@pytest_asyncio.fixture(scope="module")
async def init_module_scoped_account_declarations(
    contract_defs,
    init_module_scoped_starknet,
):
    starknet = init_module_scoped_starknet
    proxy_def, account_def, _, account_base_impl_def = contract_defs

    proxy_decl = await starknet.deprecated_declare(contract_class=proxy_def)

    account_base_impl_decl = await starknet.deprecated_declare(
        contract_class=account_base_impl_def, )

    account_decl = await starknet.deprecated_declare(
        contract_class=account_def, )

    return (
        proxy_decl,
        account_base_impl_decl,
        account_decl,
    )


@pytest_asyncio.fixture(scope="module")
async def init_module_scoped_secp256r1_accounts(
    contract_defs,
    init_module_scoped_starknet,
    init_module_scoped_account_declarations,
):
    starknet = init_module_scoped_starknet
    proxy_def, account_def, _, account_base_impl_def = contract_defs
    proxy_decl, account_base_impl_decl, account_decl = init_module_scoped_account_declarations
    signer_type_id = 2
    ecc_signer = TestECCSigner()
    # We need the below to be able to create 2 different addresses
    signer = TestSigner(123456789987654321 + signer_type_id)

    account, call_info = await deploy_account_txn(
        starknet,
        signer,
        proxy_def,
        proxy_decl,
        account_base_impl_decl,
        account_decl,
    )

    proxy = StarknetContract(
        state=starknet.state,
        abi=proxy_def.abi,
        contract_address=account.contract_address,
        constructor_call_info=call_info,
    )

    signer_payload = [
        *ecc_signer.pk_x_uint256,
        *ecc_signer.pk_y_uint256,
        signer_type_id,  # secp256r1
        0,
        0,
    ]
    response = await signer.send_transactions(
        proxy, [(proxy.contract_address, "add_signer", signer_payload)])
    signer_id = response.call_info.retdata[1]

    return (
        starknet,
        account,
        ecc_signer,
        signer_id,
        signer_type_id,
    )


@pytest_asyncio.fixture(scope="module")
async def init_module_scoped_starknet_account(
    contract_defs,
    init_module_scoped_starknet,
    init_module_scoped_account_declarations,
):
    starknet = init_module_scoped_starknet
    proxy_def, account_def, _, account_base_impl_def = contract_defs
    proxy_decl, account_base_impl_decl, account_decl = init_module_scoped_account_declarations

    signer = TestSigner(123456789987654321)
    account, call_info = await deploy_account_txn(
        starknet,
        signer,
        proxy_def,
        proxy_decl,
        account_base_impl_decl,
        account_decl,
    )

    _ = StarknetContract(
        state=starknet.state,
        abi=proxy_def.abi,
        contract_address=account.contract_address,
        constructor_call_info=call_info,
    )

    signer_type_id = 0
    signer_id = 0

    malicious_def = get_contract_def("tests/aux/Malicious.cairo")
    malicious_decl = await starknet.deprecated_declare(
        contract_class=malicious_def)
    malicious_contract = await starknet.deploy(
        class_hash=malicious_decl.class_hash, constructor_calldata=[])

    return (
        starknet,
        account,
        signer,
        signer_id,
        signer_type_id,
        malicious_contract,
    )


@pytest_asyncio.fixture
async def init_contracts(contract_defs):
    proxy_def, account_def, erc20_def, account_base_impl_def = contract_defs
    starknet = await Starknet.empty()

    account_base_impl_decl = await starknet.deprecated_declare(
        contract_class=account_base_impl_def, )

    account_decl = await starknet.deprecated_declare(
        contract_class=account_def, )

    proxy_decl = await starknet.deprecated_declare(contract_class=proxy_def)

    account, call_info = await deploy_account_txn(
        starknet,
        signer,
        proxy_def,
        proxy_decl,
        account_base_impl_decl,
        account_decl,
    )

    proxy = StarknetContract(
        state=starknet.state,
        abi=proxy_def.abi,
        contract_address=account.contract_address,
        constructor_call_info=call_info,
    )

    erc20_decl = await starknet.deprecated_declare(contract_class=erc20_def)
    erc20 = await starknet.deploy(
        class_hash=erc20_decl.class_hash,
        constructor_calldata=[
            str_to_felt("TEST_TOKEN_1"),
            str_to_felt("TST1"),
            18,
            *to_uint(10000000000),
            proxy.contract_address,
        ],
    )

    return (
        starknet,
        account_decl,
        account,
        proxy,
        erc20,
    )


@pytest.mark.asyncio
async def test_multicall_dapp_sanity(init_contracts):
    _, _, account1, _, erc20 = init_contracts

    # send_transactions uses multi-call
    response = await signer.send_transactions(
        account1,
        [
            (erc20.contract_address, "decimals", []),
            (erc20.contract_address, "totalSupply", []),
            (erc20.contract_address, "transfer", [0x12345, *to_uint(100)]),
            (erc20.contract_address, "balanceOf", [0x12345]),
        ],
    )
    assert response.call_info.retdata[1] == 18
    assert (response.call_info.retdata[2],
            response.call_info.retdata[3]) == to_uint(10000000000)
    assert response.call_info.retdata[4] == True
    assert (response.call_info.retdata[5],
            response.call_info.retdata[6]) == to_uint(100)


@pytest.mark.asyncio
async def test_external_entrypoint_guards(init_module_scoped_starknet_account):
    _, account, signer, _, _, malicious = init_module_scoped_starknet_account
    param_lengths = {
        "felt": 1,
        "felt*": 0,  # will always come after _len felt which we put 0 into
        **{
            abi_entry["name"]: abi_entry["size"]
            for abi_entry in account.abi if abi_entry["type"] == "struct"
        },
    }
    for abi_entry in account.abi:
        if (abi_entry["name"] == "initializer"
                or abi_entry["name"].startswith("__")
                or abi_entry["type"] != "function"
                or abi_entry.get("stateMutability") == "view"):
            continue
        selector = get_selector_from_name(abi_entry["name"])
        input_len = sum(
            [param_lengths[x["type"]] for x in abi_entry["inputs"]])
        await assert_revert(
            signer.send_transactions(
                account,
                [(
                    malicious.contract_address,
                    "call_other_contract",
                    [
                        account.contract_address,
                        selector,
                        input_len,
                        *([0] * input_len),
                    ],
                )],
            ),
            "caller is not",
        )


@pytest.mark.asyncio
async def test_multicall_non_existing_selector(init_contracts):
    _, _, account1, _, erc20 = init_contracts

    await assert_revert(
        signer.send_transactions(
            account1,
            [
                (erc20.contract_address, "decimals", []),
                (erc20.contract_address, "___non_existing_selector", []),
            ],
        ),
        "not found in contract",
    )


@pytest.mark.asyncio
async def test_multicall_malformed_calldata(
        init_module_scoped_starknet_account):
    _, account, _, _, _, _ = init_module_scoped_starknet_account

    # callarray states 10 calldata entries for first call, but we have 5
    calldata = [
        1,
        [
            (
                account.contract_address,
                get_selector_from_name("__some_selector__"),
                0,
                10,
            ),
        ],
        5,
        [1, 2, 3, 4, 5],
    ]

    flattened_calldata = flatten_seq(calldata)

    await assert_revert(
        signer.send_raw_invoke(account, get_selector_from_name("__execute__"),
                               flattened_calldata))


@pytest.mark.asyncio
async def test_multicall_allowed_call_to_self_combinations(
    init_module_scoped_starknet_account, ):
    _, account, signer, _, _, _ = init_module_scoped_starknet_account

    # The following combinations are allowed so they are expected to fail
    # on invalid parameters and not invalid multicall
    await assert_revert(
        signer.send_transactions(
            account,
            [
                (account.contract_address, "add_signer", []),
                (account.contract_address, "set_multisig", []),
            ],
        ),
        "While handling calldata",
    )

    await assert_revert(
        signer.send_transactions(
            account,
            [
                (account.contract_address, "disable_multisig", []),
                (account.contract_address, "remove_signer", []),
            ],
        ),
        "While handling calldata",
    )

    await assert_revert(
        signer.send_transactions(
            account,
            [
                (account.contract_address, "disable_multisig_with_etd", []),
                (account.contract_address, "remove_signer_with_etd", []),
            ],
        ),
        "While handling calldata",
    )

    await assert_revert(
        signer.send_transactions(
            account,
            [
                (account.contract_address, "cancel_deferred_remove_signer_req",
                 []),
                (account.contract_address,
                 "cancel_deferred_disable_multisig_req", []),
            ],
        ),
        "While handling calldata",
    )

    await assert_revert(
        signer.send_transactions(
            account,
            [
                (account.contract_address, "disable_multisig", []),
                (account.contract_address, "cancel_deferred_remove_signer_req",
                 []),
            ],
        ),
        "While handling calldata",
    )

    await assert_revert(
        signer.send_transactions(
            account,
            [
                (account.contract_address, "cancel_deferred_remove_signer_req",
                 []),
                (account.contract_address, "set_multisig", []),
            ],
        ),
        "While handling calldata",
    )

    # Now verify that un-authorized combinations are not possible
    # even if the first call is from an authorized combination
    await assert_revert(
        signer.send_transactions(
            account,
            [
                (account.contract_address, "add_signer", []),
                (account.contract_address, "getPublicKey", []),
            ],
        ),
        "multicall with subsequent call to self",
    )


@pytest.mark.asyncio
async def test_is_valid_sig_sanity_stark_legacy(
        init_module_scoped_starknet_account):
    _, account, _, _, _, _ = init_module_scoped_starknet_account

    hash = pedersen_hash(0x11111, 0x22222)
    sig_r, sig_s = signer.signer.sign(hash)
    await account.is_valid_signature(hash, [sig_r, sig_s]).call()


@pytest.mark.asyncio
async def test_is_valid_sig_sanity_stark_indexed(
        init_module_scoped_starknet_account):
    _, account, _, signer_id, _, _ = init_module_scoped_starknet_account

    hash = pedersen_hash(0x11111, 0x22222)
    sig_r, sig_s = signer.signer.sign(hash)
    await account.is_valid_signature(hash, [signer_id, sig_r, sig_s]).call()


@pytest.mark.asyncio
async def test_is_valid_sig_wrong_hash_stark_legacy(
    init_module_scoped_starknet_account, ):
    _, account, _, _, _, _ = init_module_scoped_starknet_account

    hash = pedersen_hash(0x11111, 0x22222)
    sig_r, sig_s = signer.signer.sign(hash)
    wrong_hash = hash + 1
    await assert_revert(
        account.is_valid_signature(wrong_hash, [sig_r, sig_s]).call(),
        "is invalid, with respect to the public key",
    )


@pytest.mark.asyncio
async def test_is_valid_sig_wrong_hash_stark_indexed(
    init_module_scoped_starknet_account, ):
    _, account, _, signer_id, _, _ = init_module_scoped_starknet_account

    hash = pedersen_hash(0x11111, 0x22222)
    sig_r, sig_s = signer.signer.sign(hash)
    wrong_hash = hash + 1
    await assert_revert(
        account.is_valid_signature(wrong_hash,
                                   [signer_id, sig_r, sig_s]).call(),
        "is invalid, with respect to the public key",
    )


@pytest.mark.asyncio
async def test_is_valid_sig_sanity_secp256r1_indexed(init_contracts):
    _, _, account1, _, _ = init_contracts

    response = await signer.send_transactions(
        account1,
        [(
            account1.contract_address,
            "add_signer",
            [
                293046774415151450209893312592299398545,
                30422779786664925426668165762677272064,
                304047604613500862221062801855681891347,
                330241335170734304790414819756797874939,
                2,  # secp256r1
                0,
                0,
            ],
        )],
    )

    signer_id = response.call_info.retdata[1]

    sig_r = [
        82985859746375978752110648250345498484,
        203775772658322124557194661410320987792,
    ]
    sig_s = [
        125334224911755631501788094602012317365,
        261186322216447006497004008229167129612,
    ]
    hash = 126207244316550804821666916

    await account1.is_valid_signature(hash, [signer_id, *sig_r, *sig_s]).call()


@pytest.mark.asyncio
async def test_invalid_secp256r1_sig(init_module_scoped_secp256r1_accounts):
    _, account, ecc_signer, signer_id, _ = init_module_scoped_secp256r1_accounts

    hash = 0

    invalid_rs = [0, 0, 0, 0]
    await assert_revert(
        account.is_valid_signature(hash, [signer_id, *invalid_rs]).call(), )

    invalid_rs = [2**139, 0, 0, 0]
    await assert_revert(
        account.is_valid_signature(hash, [signer_id, *invalid_rs]).call(), )

    invalid_rs = [0, 0, 2**139, 0]
    await assert_revert(
        account.is_valid_signature(hash, [signer_id, *invalid_rs]).call(), )

    ecc_signer: TestECCSigner
    sig = ecc_signer.sign(0xdeadbeef)
    invalid_signer_id = 0xdeadbeef
    calldata = [
        1,
        account.contract_address,
        get_selector_from_name("get_public_key"),
        0,
        0,
        0,
    ]
    await assert_revert(
        send_raw_invoke(
            account,
            get_selector_from_name("__execute__"),
            calldata=calldata,
            signature=[invalid_signer_id, *sig],
        ),
        "expected secp256r1 signer",
    )

    await assert_revert(
        send_raw_invoke(
            account,
            get_selector_from_name("__execute__"),
            calldata=calldata,
            signature=[signer_id, 0, 0, 0, 0],
        ),
        "invalid signature",
    )


@pytest.mark.asyncio
async def test_allow_multicall_single_call_to_self(
        init_module_scoped_starknet_account):
    _, account, signer, _, _, _ = init_module_scoped_starknet_account

    # send_transactions uses multi-call
    responses = await signer.send_transactions(
        account,
        [
            (account.contract_address, "getPublicKey", []),
        ],
    )

    assert responses.call_info.retdata[1] == signer.public_key


@pytest.mark.asyncio
async def test_fail_on_multicall_subsequent_call_to_self(
    init_module_scoped_starknet_account, ):
    _, account, signer, _, _, _ = init_module_scoped_starknet_account

    # send_transactions uses multi-call
    await assert_revert(
        signer.send_transactions(
            account,
            [
                (account.contract_address, "getPublicKey", []),
                (account.contract_address, "getPublicKey", []),
            ],
        ),
        "Account: multicall with subsequent call to self",
    )


@pytest.mark.asyncio
async def test_set_public_key_block(init_module_scoped_starknet_account):
    _, account, signer, _, _, _ = init_module_scoped_starknet_account

    await assert_revert(
        signer.send_transactions(
            account,
            [
                (account.contract_address, "setPublicKey", [0]),
            ],
        ),
        "is not supported",
    )


@pytest.mark.asyncio
async def test_block_reentrant_call(init_module_scoped_starknet_account):
    # Based on https://github.com/OpenZeppelin/cairo-contracts/issues/344
    starknet, account, signer, _, _, malicious = init_module_scoped_starknet_account

    await assert_revert(
        signer.send_transactions(
            account,
            [
                (malicious.contract_address, "execute_reentrancy", []),
            ],
        ),
        "Guards: no reentrant call",
    )


@pytest.mark.asyncio
async def test_add_secp256r1_signer_from_seed_and_remove_it_from_secp256r1_signer(
    init_contracts, ):
    _, _, account1, _, _ = init_contracts

    response = await signer.send_transactions(
        account1, [(account1.contract_address, "get_signers", [])])
    signer_type_id = 2
    all_signers_before = parse_get_signers_response(
        response.call_info.retdata[1:])
    expected_next_id = max([x[0] for x in all_signers_before]) + 1
    ecc_signer = TestECCSigner()
    signer_payload = [
        *ecc_signer.pk_x_uint256,
        *ecc_signer.pk_y_uint256,
        signer_type_id,  # secp256r1
        0,
        0,
    ]
    response = await signer.send_transactions(
        account1, [(account1.contract_address, "add_signer", signer_payload)])

    signer_id = response.call_info.retdata[1]
    assert signer_id == expected_next_id

    assert_event_emitted(
        response,
        from_address=account1.contract_address,
        keys="SignerAdded",
        data=[signer_id, *signer_payload],
    )

    # We shouldnt be able to add another signer (for now)
    await assert_revert(
        ecc_signer.send_transactions(
            account1,
            signer_id,
            [(
                account1.contract_address,
                "add_signer",
                [0, 0, 0, 0, signer_type_id, 0, 0],
            )],
        ),
        "can only add 1 secp256r1 signer",
    )

    # Now remove "ourselves" using hw signer
    response = await ecc_signer.send_transactions(
        account1, signer_id,
        [(account1.contract_address, "remove_signer", [signer_id])])
    assert_event_emitted(
        response,
        from_address=account1.contract_address,
        keys="SignerRemoved",
        data=[signer_id],
    )

    # Finally use seed signer to make sure we indeed removed ourselves
    # (side effect also tested: seed signer can invoke anything)
    response = await signer.send_transactions(
        account1, [(account1.contract_address, "get_signers", [])])

    all_signers_after = parse_get_signers_response(
        response.call_info.retdata[1:])

    assert all_signers_before == all_signers_after


@pytest.mark.asyncio
async def test_block_v0_txn(init_contracts):
    _, _, account1, _, _ = init_contracts

    await assert_revert(
        signer.send_transactions_v0(
            account1,
            [
                (account1.contract_address, "getPublicKey", []),
            ],
        ),
        "Please Upgrade Wallet app. Invalid transaction version.",
    )


@pytest.mark.asyncio
async def test_failure_on_adding_invalid_secp256r1_signer(init_contracts):
    _, _, account1, _, _ = init_contracts
    signer_type_id = 2
    response = await signer.send_transactions(
        account1, [(account1.contract_address, "get_signers", [])])
    all_signers = parse_get_signers_response(response.call_info.retdata[1:])
    # Verify we have an hw signer
    hw_signers = [x for x in all_signers if x[5] == 2]
    assert len(hw_signers) == 0

    not_on_curve = [
        111111111111111111111111111111111111111,
        111111111111111111111111111111111111111,
        111111111111111111111111111111111111111,
        111111111111111111111111111111111111111,
    ]
    await assert_revert(
        signer.send_transactions(
            account1,
            [(
                account1.contract_address,
                "add_signer",
                [*not_on_curve, signer_type_id, 0, 0],
            )],
        ),
        "invalid secp256r1 signer",
    )

    just_zeros = [0, 0, 0, 0]
    await assert_revert(
        signer.send_transactions(
            account1,
            [(
                account1.contract_address,
                "add_signer",
                [*just_zeros, signer_type_id, 0, 0],
            )],
        ),
        "invalid secp256r1 signer",
    )

    # invalid uint256 check
    invalid_uint256_x = [2**130, 0, 0, 0]
    await assert_revert(
        signer.send_transactions(
            account1,
            [(
                account1.contract_address,
                "add_signer",
                [*invalid_uint256_x, signer_type_id, 0, 0],
            )],
        ),
        "invalid secp256r1 signer",
    )

    invalid_uint256_y = [0, 0, 2**130, 0]
    await assert_revert(
        signer.send_transactions(
            account1,
            [(
                account1.contract_address,
                "add_signer",
                [*invalid_uint256_y, signer_type_id, 0, 0],
            )],
        ),
        "invalid secp256r1 signer",
    )


@pytest.mark.asyncio
async def test_secp256r1_signer_removal_from_seed(init_contracts):
    starknet, _, account1, _, _ = init_contracts
    signer_type_id = 2
    response = await signer.send_transactions(
        account1, [(account1.contract_address, "get_signers", [])])
    all_signers = parse_get_signers_response(response.call_info.retdata[1:])
    # Verify we have an hw signer
    hw_signers = [x for x in all_signers if x[5] == 2]
    assert len(hw_signers) == 0

    ecc_signer = TestECCSigner()
    response = await signer.send_transactions(
        account1,
        [(
            account1.contract_address,
            "add_signer",
            [
                *ecc_signer.pk_x_uint256,
                *ecc_signer.pk_y_uint256,
                signer_type_id,  # secp256r1
                0,
                0,
            ],
        )],
    )
    signer_id = response.call_info.retdata[1]

    # We have a hw signer so we can't call anything besides remove_signer with seed
    await assert_revert(
        signer.send_transactions(
            account1,
            [
                (account1.contract_address, "getPublicKey", []),
            ],
        ),
        "invalid entry point for seed signing",
    )

    # But we can use hw signer
    response = await ecc_signer.send_transactions(
        account1, signer_id, [(account1.contract_address, "getPublicKey", [])])
    assert response.call_info.retdata[1] == signer.public_key

    # make sure we can't create a remove etd on an invalid signer
    await assert_revert(
        signer.send_transactions(
            account1,
            [(account1.contract_address, "remove_signer_with_etd", [99999])]),
        "tried removing invalid signer",
    )

    # Create a deferred remove signer
    starknet.state.state.block_info = BlockInfo.create_for_testing(0, 1000)
    remove_signer_resp = await signer.send_transactions(
        account1,
        [
            (account1.contract_address, "remove_signer_with_etd", [signer_id]),
        ],
    )

    exec_info = await account1.get_deferred_remove_signer_req().call()
    assert exec_info.result.deferred_request.expire_at != 0
    raw_deferred_req_response = exec_info.call_info.result

    assert_event_emitted(
        remove_signer_resp,
        from_address=account1.contract_address,
        keys="SignerRemoveRequest",
        data=raw_deferred_req_response,
    )

    # Now try to add an additional remove signer, which should fail since we already
    # have one pending
    starknet.state.state.block_info = BlockInfo.create_for_testing(1, 1001)
    await assert_revert(
        signer.send_transactions(
            account1,
            [
                (account1.contract_address, "remove_signer_with_etd",
                 [signer_id]),
            ],
        ),
        "already have a pending remove signer request",
    )

    exec_info = await account1.get_deferred_remove_signer_req().call()
    assert exec_info.result.deferred_request.expire_at != 0
    raw_deferred_req_response = exec_info.call_info.result

    # Now set block timestamp so remove request etd will pass
    starknet.state.state.block_info = BlockInfo.create_for_testing(
        2, exec_info.result.deferred_request.expire_at + 1)

    # 1. hw signer should expire and fail to sign anything - as if it was already removed
    await assert_revert(
        ecc_signer.send_transactions(
            account1, signer_id,
            [(account1.contract_address, "getPublicKey", [])]),
        "expected secp256r1 signer",
    )

    # verify that getter takes expired etd into consideration
    exec_info = await account1.get_signers().call()
    all_signers = parse_get_signers_response(exec_info.call_info.result)
    # Verify we have an hw signer
    hw_signers = [x for x in all_signers if x[5] == 2]
    assert len(hw_signers) == 0

    # 2. seed signer should work fine and pending removal should be triggered
    # 2.1. use seed signer to "get_signers" via __execute__
    response = await signer.send_transactions(
        account1,
        [
            (account1.contract_address, "get_signers", []),
        ],
    )

    # 2.2 should result in immediate removal of hw signer due to etd expiry inside __validate__
    assert_event_emitted_in_call_info(
        response.validate_info.internal_calls[0],
        from_address=account1.contract_address,
        keys="SignerRemoved",
        data=[signer_id],
    )
    # 2.3. make sure there are no hw signers
    all_signers = parse_get_signers_response(response.call_info.retdata[1:])
    hw_signers = [x for x in all_signers if x[5] == 2]
    assert len(hw_signers) == 0
    # 2.4. make sure there is no pending removal request
    exec_info = await account1.get_deferred_remove_signer_req().call()
    assert exec_info.result.deferred_request.expire_at == 0


@pytest.mark.asyncio
async def test_swap_signers(init_contracts):
    _, _, account1, _, _ = init_contracts
    signer_type_id = 2

    response = await signer.send_transactions(
        account1, [(account1.contract_address, "get_signers", [])])
    all_signers = parse_get_signers_response(response.call_info.retdata[1:])
    # Verify we have an hw signer
    hw_signers = [x for x in all_signers if x[5] == 2]
    assert len(hw_signers) == 0
    ecc_signer = TestECCSigner()
    signer_payload = [
        *ecc_signer.pk_x_uint256,
        *ecc_signer.pk_y_uint256,
        signer_type_id,  # secp256r1
        0,
        0,
    ]
    response = await signer.send_transactions(
        account1, [(account1.contract_address, "add_signer", signer_payload)])
    signer_id = response.call_info.retdata[1]
    assert_event_emitted(
        response,
        from_address=account1.contract_address,
        keys="SignerAdded",
        data=[signer_id, *signer_payload],
    )

    ecc_signer_new = TestECCSigner()
    new_signer_payload = [
        *ecc_signer_new.pk_x_uint256,
        *ecc_signer_new.pk_y_uint256,
        signer_type_id,  # secp256r1
        0,
        0,
    ]

    swap_call = [(account1.contract_address, "swap_signers",
                  [signer_id, *new_signer_payload])]

    # Verify seed cant swap signers
    await assert_revert(
        signer.send_transactions(account1, swap_call),
        "invalid entry point for seed signing",
    )

    # Verify seed can't be swapped
    await assert_revert(
        ecc_signer.send_transactions(
            account1,
            signer_id,
            [(account1.contract_address, "swap_signers",
              [0, 0, 0, 0, 0, 1, 0, 0])],
        ),
        "cannot remove signer 0",
    )

    # Now remove old hw signer and add new hw signer in a single swap signers call
    response = await ecc_signer.send_transactions(
        account1,
        signer_id,
        swap_call,
    )
    new_signer_id = response.call_info.retdata[1]

    assert_event_emitted(
        response,
        from_address=account1.contract_address,
        keys="SignerAdded",
        data=[new_signer_id, *new_signer_payload],
    )
    assert_event_emitted(
        response,
        from_address=account1.contract_address,
        keys="SignerRemoved",
        data=[signer_id],
    )

    # Make sure there's 1 hw signer and it's the new one + verify new signer is operational
    # by get_signers using invoke and not call
    response = await ecc_signer_new.send_transactions(
        account1,
        new_signer_id,
        [
            (account1.contract_address, "get_signers", []),
        ],
    )
    all_signers = parse_get_signers_response(response.call_info.retdata[1:])
    hw_signers = [x for x in all_signers if x[5] == signer_type_id]
    assert len(hw_signers) == 1
    assert hw_signers[0][0] == new_signer_id
    assert hw_signers[0][1] == ecc_signer_new.pk_x_uint256[0]

    # Remove self
    response = await ecc_signer_new.send_transactions(
        account1,
        new_signer_id,
        [
            (account1.contract_address, "remove_signer", [new_signer_id]),
        ],
    )
    assert_event_emitted(
        response,
        from_address=account1.contract_address,
        keys="SignerRemoved",
        data=[new_signer_id],
    )

    # make sure there is no pending removal request
    exec_info = await account1.get_deferred_remove_signer_req().call()
    assert exec_info.result.deferred_request.expire_at == 0


@pytest.mark.asyncio
async def test_cancel_signer_remove_request(init_contracts):
    starknet, _, account1, _, _ = init_contracts
    signer_type_id = 2

    response = await signer.send_transactions(
        account1, [(account1.contract_address, "get_signers", [])])
    all_signers = parse_get_signers_response(response.call_info.retdata[1:])
    # Verify we have an hw signer
    hw_signers = [x for x in all_signers if x[5] == 2]
    assert len(hw_signers) == 0
    ecc_signer = TestECCSigner()
    response = await signer.send_transactions(
        account1,
        [(
            account1.contract_address,
            "add_signer",
            [
                *ecc_signer.pk_x_uint256,
                *ecc_signer.pk_y_uint256,
                signer_type_id,  # secp256r1
                0,
                0,
            ],
        )],
    )
    signer_id = response.call_info.retdata[1]

    # Create a deferred remove signer
    starknet.state.state.block_info = BlockInfo.create_for_testing(0, 1000)
    response = await signer.send_transactions(
        account1,
        [
            (account1.contract_address, "remove_signer_with_etd", [signer_id]),
        ],
    )

    exec_info = await account1.get_deferred_remove_signer_req().call()
    deferred_request = exec_info.result.deferred_request
    raw_deferred_req_response = exec_info.call_info.result
    assert deferred_request.expire_at != 0

    assert_event_emitted(
        response,
        from_address=account1.contract_address,
        keys="SignerRemoveRequest",
        data=raw_deferred_req_response,
    )

    # Cancel should fail from seed signer during etd
    starknet.state.state.block_info = BlockInfo.create_for_testing(0, 1001)
    await assert_revert(
        signer.send_transactions(
            account1,
            [
                (
                    account1.contract_address,
                    "cancel_deferred_remove_signer_req",
                    [signer_id],
                ),
            ],
        ),
        "invalid entry point for seed signing",
    )

    # Cancel should be successful during etd using hw signer
    starknet.state.state.block_info = BlockInfo.create_for_testing(0, 1002)
    response = await ecc_signer.send_transactions(
        account1,
        signer_id,
        [
            (
                account1.contract_address,
                "cancel_deferred_remove_signer_req",
                [signer_id],
            ),
        ],
    )
    assert_event_emitted(
        response,
        from_address=account1.contract_address,
        keys="SignerRemoveRequestCancelled",
        data=raw_deferred_req_response,
    )
    exec_info = await account1.get_deferred_remove_signer_req().call()
    assert exec_info.result.deferred_request.expire_at == 0


@pytest.mark.asyncio
async def test_initializer_no_secp256r1_signer(contract_defs):
    proxy_def, account_def, _, account_base_impl_def = contract_defs
    starknet = await Starknet.empty()

    proxy_decl = await starknet.deprecated_declare(contract_class=proxy_def)

    account_base_impl_decl = await starknet.deprecated_declare(
        contract_class=account_base_impl_def, )

    account_actual_impl = await starknet.deprecated_declare(
        contract_class=account_def, )

    account, call_info = await deploy_account_txn(
        starknet,
        signer,
        proxy_def,
        proxy_decl,
        account_base_impl_decl,
        account_actual_impl,
    )

    as_proxy_abi = StarknetContract(
        state=starknet.state,
        abi=proxy_def.abi,
        contract_address=account.contract_address,
        constructor_call_info=call_info,
    )

    execution_info = await as_proxy_abi.get_implementation().call()
    assert execution_info.result.implementation == account_actual_impl.class_hash

    response = await signer.send_transactions(
        account, [(account.contract_address, "get_signers", [])])
    all_signers = parse_get_signers_response(response.call_info.retdata[1:])
    # Verify we have an hw signer
    hw_signers = [x for x in all_signers if x[5] == 2]
    assert len(hw_signers) == 0 and len(all_signers) == 1


@pytest.mark.asyncio
async def test_initializer_with_secp256r1_signer(contract_defs):
    proxy_def, account_def, _, account_base_impl_def = contract_defs
    signer_type_id = 2
    starknet = await Starknet.empty()

    proxy_decl = await starknet.deprecated_declare(contract_class=proxy_def)
    account_base_impl_decl = await starknet.deprecated_declare(
        contract_class=account_base_impl_def, )

    account_actual_impl = await starknet.deprecated_declare(
        contract_class=account_def, )

    ecc_signer = TestECCSigner()
    signer_payload = [
        *ecc_signer.pk_x_uint256,
        *ecc_signer.pk_y_uint256,
        signer_type_id,  # secp256r1
        0,
        0,
    ]

    account, call_info = await deploy_account_txn(
        starknet,
        signer,
        proxy_def,
        proxy_decl,
        account_base_impl_decl,
        account_actual_impl,
        hw_signer=signer_payload,
    )

    as_proxy_abi = StarknetContract(
        state=starknet.state,
        abi=proxy_def.abi,
        contract_address=account.contract_address,
        constructor_call_info=call_info,
    )

    execution_info = await as_proxy_abi.get_implementation().call()
    assert execution_info.result.implementation == account_actual_impl.class_hash

    response = await ecc_signer.send_transactions(
        account, 1, [(account.contract_address, "get_signers", [])])
    all_signers = parse_get_signers_response(response.call_info.retdata[1:])
    # Verify we have a secp256r1 signer
    hw_signers = [x for x in all_signers if x[5] == signer_type_id]
    assert len(hw_signers) == 1 and len(all_signers) == 2


@pytest.mark.asyncio
async def test_initializer_fail_on_no_actual_impl(contract_defs):
    proxy_def, _, _, account_base_impl_def = contract_defs
    starknet = await Starknet.empty()

    account_base_impl_decl = await starknet.deprecated_declare(
        contract_class=account_base_impl_def, )
    proxy_decl = await starknet.deprecated_declare(contract_class=proxy_def)

    await assert_revert(
        deploy_account_txn(
            starknet,
            signer,
            proxy_def,
            proxy_decl,
            account_base_impl_decl,
            account_actual_impl=None,
            hw_signer=None,
        ),
        "invalid actual implementation",
    )


@pytest.mark.asyncio
async def test_set_multisig_basic_assertions(init_contracts):
    _, _, account1, _, _ = init_contracts

    await assert_revert(
        signer.send_transactions(
            account1, [(account1.contract_address, "set_multisig", [3])]),
        "multisig currently supports 2 signers only",
    )

    await assert_revert(
        signer.send_transactions(
            account1, [(account1.contract_address, "set_multisig", [2])]),
        "multisig can only be set if account have additional signers",
    )


@pytest.mark.asyncio
async def test_set_multisig_add_signer_multicall(init_contracts):
    _, _, account1, _, _ = init_contracts

    ecc_signer = TestECCSigner()
    response = await signer.send_transactions(
        account1,
        [
            (
                account1.contract_address,
                "add_signer",
                [
                    *ecc_signer.pk_x_uint256,
                    *ecc_signer.pk_y_uint256,
                    2,  # secp256r1
                    0,
                    0,
                ],
            ),
            (account1.contract_address, "set_multisig", [2]),
        ],
    )

    assert_event_emitted(response,
                         from_address=account1.contract_address,
                         keys="MultisigSet",
                         data=[2])

    execution_info = await account1.get_multisig().call()
    assert execution_info.result.multisig_num_signers == 2


@pytest.mark.asyncio
async def test_set_multisig_existing_hws_signer(init_contracts):
    _, _, account1, _, _ = init_contracts

    ecc_signer = TestECCSigner()

    response = await signer.send_transactions(
        account1,
        [(
            account1.contract_address,
            "add_signer",
            [
                *ecc_signer.pk_x_uint256,
                *ecc_signer.pk_y_uint256,
                2,  # secp256r1
                0,
                0,
            ],
        )],
    )
    signer_id = response.call_info.retdata[1]

    # seed should not be able to enable multisig
    await assert_revert(
        signer.send_transactions(
            account1, [(account1.contract_address, "set_multisig", [2])]),
        "invalid entry point for seed signing",
    )

    # enable multisig from hws
    response = await ecc_signer.send_transactions(
        account1, signer_id,
        [(account1.contract_address, "set_multisig", [2])])

    assert_event_emitted(response,
                         from_address=account1.contract_address,
                         keys="MultisigSet",
                         data=[2])

    execution_info = await account1.get_multisig().call()
    assert execution_info.result.multisig_num_signers == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("first_signer_type", ["secp256r1", "seed"])
async def test_multisig_with_multi_signers(init_contracts, first_signer_type):
    _, _, account1, _, _ = init_contracts

    ecc_signer = TestECCSigner()

    response = await signer.send_transactions(
        account1,
        [
            (
                account1.contract_address,
                "add_signer",
                [
                    *ecc_signer.pk_x_uint256,
                    *ecc_signer.pk_y_uint256,
                    2,  # secp256r1
                    0,
                    0,
                ],
            ),
            (account1.contract_address, "set_multisig", [2]),
        ],
    )
    signer_id = response.call_info.retdata[1]

    # Setup send_transactions according to parametrized first_singer
    # rest of the flow after setup is generic
    if first_signer_type == "secp256r1":
        send_transactions_1st = ecc_signer.send_transactions
        signer_id_param_1st = [signer_id]
        send_transactions_2nd = signer.send_transactions
        signer_id_param_2nd = []
        first_signer_id = signer_id
        second_signer_id = 0
    else:
        send_transactions_1st = signer.send_transactions
        signer_id_param_1st = []
        send_transactions_2nd = ecc_signer.send_transactions
        signer_id_param_2nd = [signer_id]
        first_signer_id = 0
        second_signer_id = signer_id

    # Fail on no pending txn
    await assert_revert(
        send_transactions_1st(*[
            account1,
            *signer_id_param_1st,
            [(
                account1.contract_address,
                "sign_pending_multisig_transaction",
                [0, 0, 0, 0],
            )],
        ]),
        "no pending transaction to sign",
    )

    # But allow estimate fee with seed with any calldata
    # should fail on invalid contract but *not* invalid hash
    await assert_revert(
        signer.estimate_fee(
            account1,
            [
                (
                    account1.contract_address,
                    "sign_pending_multisig_transaction",
                    [
                        6,
                        1,
                        1,
                        1,
                        0,
                        0,
                        0,  # Some fake call to contract at 0x1
                        0,
                        0,
                        0,  # invalid nonce, maxfee and txn ver
                    ],
                ),
            ],
        ),
        "Requested contract address 0x1 is not deployed",
    )

    # Send first signer
    response = await send_transactions_1st(*[
        account1,
        *signer_id_param_1st,
        [(account1.contract_address, "getPublicKey", [])],
    ])

    assert response.call_info.retdata[0] == 0

    execution_info = await account1.get_pending_multisig_transaction().call()
    assert (execution_info.result.pending_multisig_transaction.signer_1_id ==
            first_signer_id, )
    pending_hash = execution_info.result.pending_multisig_transaction.transaction_hash
    expire_at_sec = execution_info.result.pending_multisig_transaction.expire_at_sec
    expire_at_block_num = (
        execution_info.result.pending_multisig_transaction.expire_at_block_num)

    assert_event_emitted(
        response,
        from_address=account1.contract_address,
        keys=[
            get_selector_from_name("MultisigPendingTransaction"),
            first_signer_id
        ],
        data=[pending_hash, expire_at_sec, expire_at_block_num],
    )

    # Fail on same signer
    await assert_revert(
        send_transactions_1st(*[
            account1,
            *signer_id_param_1st,
            [(
                account1.contract_address,
                "sign_pending_multisig_transaction",
                [0, 0, 0, 0],
            )],
        ]),
        "multisig signer can only sign once",
    )

    # Now send with 2nd signer, fail on invalid hash
    await assert_revert(
        send_transactions_2nd(*[
            account1,
            *signer_id_param_2nd,
            [
                (
                    account1.contract_address,
                    "sign_pending_multisig_transaction",
                    [0, 0, 0, 0],
                ),
            ],
        ]),
        "multisig invalid hash",
    )

    # But allow estimate fee with seed with any calldata
    # should fail on invalid contract but *not* invalid hash
    await assert_revert(
        signer.estimate_fee(
            account1,
            [
                (
                    account1.contract_address,
                    "sign_pending_multisig_transaction",
                    [
                        6,
                        1,
                        1,
                        1,
                        0,
                        0,
                        0,  # Some fake call to contract at 0x1
                        0,
                        0,
                        0,  # invalid nonce, maxfee and txn ver
                    ],
                ),
            ],
        ),
        "Requested contract address 0x1 is not deployed",
    )

    second_signer_calls = [(
        account1.contract_address,
        "sign_pending_multisig_transaction",
        [
            # raw calldata_len:
            6,
            # raw calldata for execute (callarray len, call array, calldata len, calldata) on getPublicKey
            1,
            account1.contract_address,
            get_selector_from_name("getPublicKey"),
            0,
            0,
            0,
            # pending nonce
            2,
            # pending max fee
            0,
            # txn ver
            1,
        ],
    )]

    response = await send_transactions_2nd(
        *[account1, *signer_id_param_2nd, second_signer_calls])

    # we index 2 below because we get raw __execute__ output wrapped in sign_pending_multisig_transaction output
    # i.e. (response_len=<sign_pending_multisig_transaction len>, response=(respones_len=<execute len>, response=<execute resp>))
    assert response.call_info.retdata[2] == signer.public_key

    assert_event_emitted(
        response,
        from_address=account1.contract_address,
        keys=[
            get_selector_from_name("MultisigPendingTransactionSigned"),
            pending_hash
        ],
        data=[second_signer_id],
    )

    # pending should've been cleared
    execution_info = await account1.get_pending_multisig_transaction().call()
    assert execution_info.result.pending_multisig_transaction.transaction_hash == 0


@pytest.mark.asyncio
async def test_multisig_2_signers_in_single_sig(init_contracts):
    _, _, account1, _, erc20 = init_contracts

    ecc_signer = TestECCSigner()

    response = await signer.send_transactions(
        account1,
        [
            (
                account1.contract_address,
                "add_signer",
                [
                    *ecc_signer.pk_x_uint256,
                    *ecc_signer.pk_y_uint256,
                    2,  # secp256r1
                    0,
                    0,
                ],
            ),
            (account1.contract_address, "set_multisig", [2]),
        ],
    )
    signer_id = response.call_info.retdata[1]

    # Prepare execute calldata for both signers to sign
    calldata = [
        1, erc20.contract_address,
        get_selector_from_name("balanceOf"), 0, 1, 1, account1.contract_address
    ]

    # valid case
    signer_obj = namedtuple(
        'SignerTuple',
        ['sign'
         ])(lambda tx_hash:
            [0, *signer.signer.sign(tx_hash), signer_id, *ecc_signer.sign(tx_hash)])
    await send_raw_invoke(
        account1,
        get_selector_from_name("__execute__"),
        calldata,
        signer=signer_obj,
    )

    async def _invalid_case(sig, error_msg):
        invalid_signer_obj = namedtuple('_st', ['sign'])(lambda tx_hash: sig(tx_hash))
        await assert_revert(
            send_raw_invoke(
                account1,
                get_selector_from_name("__execute__"),
                calldata,
                signer=invalid_signer_obj,
            ),
            error_msg,
        )

    # invalid signature format - dup stark signer
    await _invalid_case(
        lambda tx_hash: [0, *signer.signer.sign(tx_hash), 0, *signer.signer.sign(tx_hash)],
        "unexpected signature",
    )

    # invalid signature - wrong stark sig
    await _invalid_case(
        lambda tx_hash: [0, *[x + 1 for x in signer.signer.sign(tx_hash)], signer_id, *ecc_signer.sign(tx_hash)],
        "invalid signature",
    )

    # invalid signature format - dup secp256r1 signer
    await _invalid_case(
        lambda tx_hash: [signer_id, *ecc_signer.sign(tx_hash), signer_id, *ecc_signer.sign(tx_hash)],
        "unexpected signature",
    )

    # invalid signature - wrong secp256r1 sig
    await _invalid_case(
        lambda tx_hash: [0, *signer.signer.sign(tx_hash), signer_id, *[x + 1 for x in ecc_signer.sign(tx_hash)]],
        "invalid signature",
    )


@pytest.mark.asyncio
async def test_multisig_override_pending_txn(init_contracts):
    _, _, account1, _, _ = init_contracts

    ecc_signer = TestECCSigner()

    response = await signer.send_transactions(
        account1,
        [
            (
                account1.contract_address,
                "add_signer",
                [
                    *ecc_signer.pk_x_uint256,
                    *ecc_signer.pk_y_uint256,
                    2,  # secp256r1
                    0,
                    0,
                ],
            ),
            (account1.contract_address, "set_multisig", [2]),
        ],
    )
    signer_id = response.call_info.retdata[1]
    # secp256r1 signer initiates the multisig
    response = await ecc_signer.send_transactions(
        account1, signer_id, [(account1.contract_address, "getPublicKey", [])])
    assert response.call_info.retdata[0] == 0
    execution_info = await account1.get_pending_multisig_transaction().call()
    deferred_txn_1 = execution_info.result.pending_multisig_transaction

    # seed signer overrides
    await assert_revert(
        signer.send_transactions(
            account1, [(account1.contract_address, "getPublicKey", [])]),
        "seed signer cannot override pending transactions",
    )


@pytest.mark.asyncio
async def test_multisig_discard_expired_pending_txn(init_contracts):
    starknet, _, account1, _, _ = init_contracts

    ecc_signer = TestECCSigner()

    response = await signer.send_transactions(
        account1,
        [
            (
                account1.contract_address,
                "add_signer",
                [
                    *ecc_signer.pk_x_uint256,
                    *ecc_signer.pk_y_uint256,
                    2,  # secp256r1
                    0,
                    0,
                ],
            ),
            (account1.contract_address, "set_multisig", [2]),
        ],
    )
    signer_id = response.call_info.retdata[1]
    # 1st multisig txn - nonce == 2
    response = await ecc_signer.send_transactions(
        account1, signer_id, [(account1.contract_address, "getPublicKey", [])])
    assert response.call_info.retdata[0] == 0

    execution_info = await account1.get_pending_multisig_transaction().call()
    deferred_txn = execution_info.result.pending_multisig_transaction
    assert deferred_txn.transaction_hash != 0

    # expire block alone should not discard
    starknet.state.state.block_info = BlockInfo.create_for_testing(5, 1)
    response = await signer.send_transactions(
        account1,
        [
            (
                account1.contract_address,
                "sign_pending_multisig_transaction",
                [
                    # raw calldata_len:
                    6,
                    # raw calldata for execute (callarray len, call array, calldata len, calldata)
                    1,
                    account1.contract_address,
                    get_selector_from_name("getPublicKey"),
                    0,
                    0,
                    0,
                    # pending nonce
                    2,
                    # pending max fee
                    0,
                    # txn ver
                    1,
                ],
            ),
        ],
    )
    assert response.call_info.retdata[2] == signer.public_key

    # time-based expiry alone should not discard
    starknet.state.state.block_info = BlockInfo.create_for_testing(0, 0)
    # 2nd multisig txn - nonce == 4
    response = await ecc_signer.send_transactions(
        account1, signer_id, [(account1.contract_address, "getPublicKey", [])])
    assert response.call_info.retdata[0] == 0
    starknet.state.state.block_info = BlockInfo.create_for_testing(0, 250)
    response = await signer.send_transactions(
        account1,
        [
            (
                account1.contract_address,
                "sign_pending_multisig_transaction",
                [
                    # raw calldata_len:
                    6,
                    # raw calldata for execute (callarray len, call array, calldata len, calldata) on getPublicKey
                    1,
                    account1.contract_address,
                    get_selector_from_name("getPublicKey"),
                    0,
                    0,
                    0,
                    # pending nonce
                    4,
                    # pending max fee
                    0,
                    # txn ver
                    1,
                ],
            ),
        ],
    )
    assert response.call_info.retdata[2] == signer.public_key

    # Both block and time-based expiry should expire the pending txn
    starknet.state.state.block_info = BlockInfo.create_for_testing(0, 0)
    # 2nd multisig txn - nonce == 6
    response = await ecc_signer.send_transactions(
        account1, signer_id, [(account1.contract_address, "getPublicKey", [])])
    starknet.state.state.block_info = BlockInfo.create_for_testing(5, 301)
    await assert_revert(
        signer.send_transactions(
            account1,
            [
                (
                    account1.contract_address,
                    "sign_pending_multisig_transaction",
                    [
                        # raw calldata_len:
                        6,
                        # raw calldata for execute (callarray len, call array, calldata len, calldata)
                        1,
                        account1.contract_address,
                        get_selector_from_name("getPublicKey"),
                        0,
                        0,
                        0,
                        # pending nonce
                        6,
                        # pending max fee
                        0,
                        # txn ver
                        1,
                    ],
                ),
            ],
        ),
        "no pending transaction to sign",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("disable_multisig_initiator", ["secp256r1", "seed"])
async def test_multisig_disable(init_contracts, disable_multisig_initiator):
    _, _, account1, _, _ = init_contracts

    ecc_signer = TestECCSigner()

    response = await signer.send_transactions(
        account1,
        [
            (
                account1.contract_address,
                "add_signer",
                [
                    *ecc_signer.pk_x_uint256,
                    *ecc_signer.pk_y_uint256,
                    2,  # secp256r1
                    0,
                    0,
                ],
            ),
            (account1.contract_address, "set_multisig", [2]),
        ],
    )
    signer_id = response.call_info.retdata[1]

    # Create a pending txn only for secp256r1 signer
    # seed is not allowed to override
    if disable_multisig_initiator == "secp256r1":
        response = await ecc_signer.send_transactions(
            account1, signer_id,
            [(account1.contract_address, "getPublicKey", [])])
        assert response.call_info.retdata[0] == 0

    if disable_multisig_initiator == "secp256r1":
        # Override pending with disable multisig (nonce == 3)
        response = await ecc_signer.send_transactions(
            account1, signer_id,
            [(account1.contract_address, "disable_multisig", [])])
    else:
        response = await signer.send_transactions(
            account1, [(account1.contract_address, "disable_multisig", [])])
    assert response.call_info.retdata[0] == 0

    # Seed should not be able to do anything besides signing the pending txn or sending etd txns
    # should fail
    if disable_multisig_initiator == "secp256r1":
        await assert_revert(
            signer.send_transactions(
                account1,
                [
                    (account1.contract_address, "getPublicKey", []),
                ],
            ),
            "seed signer cannot override pending transactions",
        )

        # should be ok
        _ = await signer.send_transactions(
            account1,
            [
                (account1.contract_address, "disable_multisig_with_etd", []),
            ],
        )

    # execute it
    sign_pending_call_array = [(
        account1.contract_address,
        "sign_pending_multisig_transaction",
        [
            # raw calldata_len:
            6,
            # raw calldata for execute (callarray len, call array, calldata len, calldata)
            1,
            account1.contract_address,
            get_selector_from_name("disable_multisig"),
            0,
            0,
            0,
            # pending nonce
            3 if disable_multisig_initiator == "secp256r1" else 2,
            # pending max fee
            0,
            # txn ver
            1,
        ],
    )]

    if disable_multisig_initiator == "secp256r1":
        response = await signer.send_transactions(
            account1,
            sign_pending_call_array,
        )
    else:
        response = await ecc_signer.send_transactions(
            account1,
            signer_id,
            sign_pending_call_array,
        )

    # Make sure multi sig remove event fired
    assert_event_emitted(
        response,
        from_address=account1.contract_address,
        keys="MultisigDisabled",
        data=[],
    )

    # Make sure no multisig
    execution_info = await account1.get_multisig().call()
    assert execution_info.result.multisig_num_signers == 0

    # Make sure no pending multisig txns
    execution_info = await account1.get_pending_multisig_transaction().call()
    assert execution_info.result.pending_multisig_transaction.transaction_hash == 0


@pytest.mark.asyncio
async def test_multisig_remove_signer_should_disable_multisig(init_contracts):
    _, _, account1, _, _ = init_contracts

    ecc_signer = TestECCSigner()

    response = await signer.send_transactions(
        account1,
        [
            (
                account1.contract_address,
                "add_signer",
                [
                    *ecc_signer.pk_x_uint256,
                    *ecc_signer.pk_y_uint256,
                    2,  # secp256r1
                    0,
                    0,
                ],
            ),
            (account1.contract_address, "set_multisig", [2]),
        ],
    )
    signer_id = response.call_info.retdata[1]

    # Make sure that there is multisig
    execution_info = await account1.get_multisig().call()
    assert execution_info.result.multisig_num_signers == 2

    # initiate remove hws signer from seed
    # note this is not possible without multisig - so we also test that
    _ = await signer.send_transactions(
        account1, [(account1.contract_address, "remove_signer", [signer_id])])
    response = await ecc_signer.send_transactions(
        account1,
        signer_id,
        [
            (
                account1.contract_address,
                "sign_pending_multisig_transaction",
                [
                    # raw calldata_len:
                    7,
                    # raw calldata for execute (callarray len, call array, calldata len, calldata)
                    1,
                    account1.contract_address,
                    get_selector_from_name("remove_signer"),
                    0,
                    1,
                    1,
                    signer_id,
                    # pending nonce
                    2,
                    # pending max fee
                    0,
                    # txn ver
                    1,
                ],
            ),
        ],
    )

    assert_event_emitted(
        response,
        from_address=account1.contract_address,
        keys="MultisigDisabled",
        data=[],
    )
    # Make sure no multisig
    execution_info = await account1.get_multisig().call()
    assert execution_info.result.multisig_num_signers == 0

    # Make sure no pending multisig txns
    execution_info = await account1.get_pending_multisig_transaction().call()
    assert execution_info.result.pending_multisig_transaction.transaction_hash == 0


@pytest.mark.asyncio
async def test_multisig_disable_with_etd_block_unauthorized_multicall(
        init_contracts):
    # Although this is covered by allowed multicall combinations, check this explicitly as well
    starknet, _, account1, _, _ = init_contracts

    ecc_signer = TestECCSigner()

    response = await signer.send_transactions(
        account1,
        [
            (
                account1.contract_address,
                "add_signer",
                [
                    *ecc_signer.pk_x_uint256,
                    *ecc_signer.pk_y_uint256,
                    2,  # secp256r1
                    0,
                    0,
                ],
            ),
            (account1.contract_address, "set_multisig", [2]),
        ],
    )
    signer_id = response.call_info.retdata[1]

    # disable with etd is not possible with non-seed signer
    await assert_revert(
        ecc_signer.send_transactions(
            account1,
            signer_id,
            [
                (account1.contract_address, "disable_multisig_with_etd", []),
            ],
        ),
        "should be called with seed signer",
    )

    await assert_revert(
        signer.send_transactions(account1, [
            (account1.contract_address, "disable_multisig_with_etd", []),
            (account1.contract_address, "remove_signer", [1]),
        ]),
        "multicall with subsequent call to self",
    )


@pytest.mark.asyncio
async def test_multisig_disable_with_etd(init_contracts):
    starknet, _, account1, _, _ = init_contracts

    ecc_signer = TestECCSigner()

    response = await signer.send_transactions(
        account1,
        [
            (
                account1.contract_address,
                "add_signer",
                [
                    *ecc_signer.pk_x_uint256,
                    *ecc_signer.pk_y_uint256,
                    2,  # secp256r1
                    0,
                    0,
                ],
            ),
            (account1.contract_address, "set_multisig", [2]),
        ],
    )
    signer_id = response.call_info.retdata[1]

    # disable with etd is not possible with non-seed signer
    await assert_revert(
        ecc_signer.send_transactions(
            account1,
            signer_id,
            [
                (account1.contract_address, "disable_multisig_with_etd", []),
            ],
        ),
        "should be called with seed signer",
    )

    response = await signer.send_transactions(
        account1,
        [
            (account1.contract_address, "disable_multisig_with_etd", []),
            (account1.contract_address, "remove_signer_with_etd", [signer_id]),
        ],
    )

    # Should not be able to call another disable multisig
    await assert_revert(
        signer.send_transactions(
            account1,
            [
                (account1.contract_address, "disable_multisig_with_etd", []),
            ],
        ),
        "already have a pending disable multisig request",
    )

    # Make sure no multisig as both calls above are not deferred by execution logic
    execution_info = await account1.get_pending_multisig_transaction().call()
    assert execution_info.result.pending_multisig_transaction.transaction_hash == 0

    # Make sure we have a deferred request
    exec_info = await account1.get_deferred_disable_multisig_req().call()
    deferred_request = exec_info.result.deferred_request
    raw_deferred_req_response = exec_info.call_info.result
    assert deferred_request.expire_at != 0

    # And that an event was emitted
    assert_event_emitted(
        response,
        from_address=account1.contract_address,
        keys="MultisigDisableRequest",
        data=raw_deferred_req_response,
    )

    starknet.state.state.block_info = BlockInfo.create_for_testing(
        0, deferred_request.expire_at + 1)

    # Check the getter also considers expired etd
    exec_info = await account1.get_multisig().call()
    assert exec_info.result.multisig_num_signers == 0

    # Deferred expired so we expect multisig to be removed, i.e. txn will execute as usual
    response = await signer.send_transactions(
        account1, [(account1.contract_address, "getPublicKey", [])])
    assert_event_emitted_in_call_info(
        response.validate_info.internal_calls[0],
        from_address=account1.contract_address,
        keys="MultisigDisabled",
        data=[],
    )
    assert response.call_info.retdata[1] == signer.public_key


@pytest.mark.asyncio
async def test_multisig_disable_after_remove_signer_etd_expire(init_contracts):
    starknet, _, account1, _, _ = init_contracts

    ecc_signer = TestECCSigner()

    response = await signer.send_transactions(
        account1,
        [
            (
                account1.contract_address,
                "add_signer",
                [
                    *ecc_signer.pk_x_uint256,
                    *ecc_signer.pk_y_uint256,
                    2,  # secp256r1
                    0,
                    0,
                ],
            ),
            (account1.contract_address, "set_multisig", [2]),
        ],
    )
    signer_id = response.call_info.retdata[1]

    response = await signer.send_transactions(
        account1,
        [
            (account1.contract_address, "remove_signer_with_etd", [signer_id]),
        ],
    )

    # Make sure no multisig deferred txn as remove_signer_with_etd should not be deferred
    execution_info = await account1.get_pending_multisig_transaction().call()
    assert execution_info.result.pending_multisig_transaction.transaction_hash == 0

    # Make sure we have a deferred request
    exec_info = await account1.get_deferred_remove_signer_req().call()
    deferred_request = exec_info.result.deferred_request
    assert deferred_request.expire_at != 0

    starknet.state.state.block_info = BlockInfo.create_for_testing(
        0, deferred_request.expire_at + 1)

    # Deferred remove signer expired so we expect multisig to be removed,
    # i.e. txn will execute as usual
    response = await signer.send_transactions(
        account1, [(account1.contract_address, "getPublicKey", [])])
    assert_event_emitted_in_call_info(
        response.validate_info.internal_calls[0],
        from_address=account1.contract_address,
        keys="MultisigDisabled",
        data=[],
    )

    assert response.call_info.retdata[1] == signer.public_key


@pytest.mark.asyncio
async def test_multisig_allow_seed_to_swap_signers(init_contracts):
    _, _, account1, _, _ = init_contracts

    ecc_signer = TestECCSigner()
    add_signer_payload = [
        *ecc_signer.pk_x_uint256,
        *ecc_signer.pk_y_uint256,
        2,  # secp256r1
        0,
        0,
    ]

    ecc_signer_2 = TestECCSigner()
    add_signer_2_payload = [
        *ecc_signer_2.pk_x_uint256,
        *ecc_signer_2.pk_y_uint256,
        2,  # secp256r1
        0,
        0,
    ]

    response = await signer.send_transactions(
        account1,
        [
            (account1.contract_address, "add_signer", add_signer_payload),
            (account1.contract_address, "set_multisig", [2]),
        ],
    )
    signer_id = response.call_info.retdata[1]
    swap_signers_calldata = [signer_id, *add_signer_2_payload]
    # Start with seed
    response = await signer.send_transactions(
        account1,
        [
            (account1.contract_address, "swap_signers", swap_signers_calldata),
        ],
    )

    # sign pending with original secp256r1 signer
    response = await ecc_signer.send_transactions(
        account1,
        signer_id,
        [
            (
                account1.contract_address,
                "sign_pending_multisig_transaction",
                [
                    # raw calldata_len:
                    6 + len(swap_signers_calldata),
                    # raw calldata for execute (callarray len, call array, calldata len, calldata)
                    1,
                    account1.contract_address,
                    get_selector_from_name("swap_signers"),
                    0,
                    len(swap_signers_calldata),
                    len(swap_signers_calldata),
                    *swap_signers_calldata,
                    # pending nonce
                    2,
                    # pending max fee
                    0,
                    # txn ver
                    1,
                ],
            ),
        ],
    )
    new_signer_id = response.call_info.retdata[2]

    # Now start with secp256r1 signer and finalize with seed
    swap_signers_calldata = [new_signer_id, *add_signer_payload]

    response = await ecc_signer_2.send_transactions(
        account1,
        new_signer_id,
        [
            (account1.contract_address, "swap_signers", swap_signers_calldata),
        ],
    )
    # And sign pending with seed
    response = await signer.send_transactions(
        account1,
        [
            (
                account1.contract_address,
                "sign_pending_multisig_transaction",
                [
                    # raw calldata_len:
                    6 + len(swap_signers_calldata),
                    # raw calldata for execute (callarray len, call array, calldata len, calldata)
                    1,
                    account1.contract_address,
                    get_selector_from_name("swap_signers"),
                    0,
                    len(swap_signers_calldata),
                    len(swap_signers_calldata),
                    *swap_signers_calldata,
                    # pending nonce
                    4,
                    # pending max fee
                    0,
                    # txn ver
                    1,
                ],
            ),
        ],
    )
    new_signer_id = response.call_info.retdata[2]


@pytest.mark.asyncio
async def test_multisig_cancel_disable_with_etd(init_contracts):
    starknet, _, account1, _, _ = init_contracts

    ecc_signer = TestECCSigner()

    response = await signer.send_transactions(
        account1,
        [
            (
                account1.contract_address,
                "add_signer",
                [
                    *ecc_signer.pk_x_uint256,
                    *ecc_signer.pk_y_uint256,
                    2,  # secp256r1
                    0,
                    0,
                ],
            ),
            (account1.contract_address, "set_multisig", [2]),
        ],
    )
    signer_id = response.call_info.retdata[1]

    # disable with etd
    response = await signer.send_transactions(
        account1,
        [
            (account1.contract_address, "disable_multisig_with_etd", []),
            (account1.contract_address, "remove_signer_with_etd", [signer_id]),
        ],
    )

    # Verify that we dont have a deferred txn
    exec_info = await account1.get_deferred_disable_multisig_req().call()
    assert exec_info.result.deferred_request.expire_at != 0

    # now cancel it with multisig
    starknet.state.state.block_info = BlockInfo.create_for_testing(1, 1)
    response = await signer.send_transactions(
        account1,
        [
            (
                account1.contract_address,
                "cancel_deferred_remove_signer_req",
                [signer_id],
            ),
            (account1.contract_address, "cancel_deferred_disable_multisig_req",
             []),
        ],
    )
    assert response.call_info.retdata[0] == 0

    # Note: we also test multi-call deferred multisig txn signing
    response = await ecc_signer.send_transactions(
        account1,
        signer_id,
        [
            (
                account1.contract_address,
                "sign_pending_multisig_transaction",
                [
                    # raw calldata_len:
                    11,
                    # raw calldata for execute (callarray len, call array, calldata len, calldata)
                    2,
                    account1.contract_address,
                    get_selector_from_name(
                        "cancel_deferred_remove_signer_req"),
                    0,
                    1,
                    account1.contract_address,
                    get_selector_from_name(
                        "cancel_deferred_disable_multisig_req"),
                    1,
                    0,
                    1,
                    signer_id,
                    # pending nonce
                    3,
                    # pending max fee
                    0,
                    # txn ver
                    1,
                ],
            ),
        ],
    )

    # Verify that we dont have a deferred req
    exec_info = await account1.get_deferred_disable_multisig_req().call()
    assert exec_info.result.deferred_request.expire_at == 0


@pytest.mark.asyncio
async def test_declare_validation(init_contracts, contract_defs):
    proxy_def, _, _, _ = contract_defs
    _, _, account1, _, _ = init_contracts

    # Create a dummy declare tx
    declare_tx_params = {
        "contract_class": proxy_def,
        "chain_id": StarknetChainId.TESTNET.value,
        "sender_address": account1.contract_address,
        "max_fee": 0,
        "version": 1,
        "signature": [],
    }
    declare_tx = InternalDeclare.create_deprecated(
        **{
            **declare_tx_params, "nonce": 1
        })
    seed_sig = signer.signer.sign(declare_tx.hash_value)
    declare_tx.__dict__["signature"] = list(seed_sig)
    # Seed mode
    await account1.state.execute_tx(tx=declare_tx)

    ecc_signer = TestECCSigner()
    signer_payload = [
        *ecc_signer.pk_x_uint256,
        *ecc_signer.pk_y_uint256,
        2,  # secp256r1
        0,
        0,
    ]
    response = await signer.send_transactions(
        account1, [(account1.contract_address, "add_signer", signer_payload)])
    signer_id = response.call_info.retdata[1]

    # HWS mode
    declare_tx = InternalDeclare.create_deprecated(
        **{
            **declare_tx_params, "nonce": 3
        })
    hws_sig = ecc_signer.sign(declare_tx.hash_value)
    declare_tx.__dict__["signature"] = [signer_id, *hws_sig]
    await account1.state.execute_tx(tx=declare_tx)

    # Multisig mode
    await ecc_signer.send_transactions(
        account1, signer_id,
        [(account1.contract_address, "set_multisig", [2])])
    declare_tx = InternalDeclare.create_deprecated(
        **{
            **declare_tx_params, "nonce": 5
        })
    hws_sig = ecc_signer.sign(declare_tx.hash_value)
    seed_sig = signer.signer.sign(declare_tx.hash_value)
    declare_tx.__dict__["signature"] = [
        0, *list(seed_sig), signer_id, *hws_sig
    ]
    await account1.state.execute_tx(tx=declare_tx)


@pytest.mark.asyncio
async def test_is_valid_sig_for_mode(init_contracts):
    _, _, account1, _, _ = init_contracts

    test_hash = 0x1234
    seed_sig = list(signer.signer.sign(test_hash))

    # seed
    exec_info = await account1.isValidSignature(test_hash, seed_sig).call()
    assert exec_info.result.isValid == 1

    ecc_signer = TestECCSigner()
    signer_payload = [
        *ecc_signer.pk_x_uint256,
        *ecc_signer.pk_y_uint256,
        2,  # secp256r1
        0,
        0,
    ]
    response = await signer.send_transactions(
        account1, [(account1.contract_address, "add_signer", signer_payload)])
    signer_id = response.call_info.retdata[1]

    # HWS mode
    # Fail on seed sig
    exec_info = await account1.isValidSignature(test_hash, seed_sig).call()
    assert exec_info.result.isValid == 0
    # But succeed on HWS
    hws_sig = ecc_signer.sign(test_hash)
    exec_info = await account1.isValidSignature(test_hash,
                                                [signer_id, *hws_sig]).call()
    assert exec_info.result.isValid == 1

    # Multisig mode
    await ecc_signer.send_transactions(
        account1, signer_id,
        [(account1.contract_address, "set_multisig", [2])])
    # Fail on seed sig
    exec_info = await account1.isValidSignature(test_hash, seed_sig).call()
    assert exec_info.result.isValid == 0
    # Fail on HWS
    hws_sig = ecc_signer.sign(test_hash)
    exec_info = await account1.isValidSignature(test_hash,
                                                [signer_id, *hws_sig]).call()
    assert exec_info.result.isValid == 0
    # But succeed on Multisig
    exec_info = await account1.isValidSignature(
        test_hash, [0, *seed_sig, signer_id, *hws_sig]).call()
    assert exec_info.result.isValid == 1
