import pytest
import pytest_asyncio

from starkware.cairo.lang.vm.crypto import pedersen_hash
from starkware.starknet.public.abi import get_selector_from_name, starknet_keccak
from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.testing.starknet import StarknetContract
from starkware.starknet.services.api.contract_class import ContractClass


from utils import (
    TestSigner,
    assert_revert,
    assert_event_emitted,
    contract_path,
    get_contract_def,
    parse_get_signers_response,
    deploy_account_txn,
    str_to_felt,
)


IACCOUNT_ID = 0xF10DBD44


signer = TestSigner(123456789987654321)
signer2 = TestSigner(987654321123456789)


@pytest.fixture(scope="module")
def contract_defs():
    proxy_def = get_contract_def("lib/openzeppelin/upgrades/Proxy.cairo")
    account_base_impl_def = get_contract_def("account/AccountBaseImpl.cairo")
    account_def = get_contract_def("account/Account.cairo")

    return proxy_def, account_def, account_base_impl_def


@pytest_asyncio.fixture
async def proxy_init(contract_defs):
    proxy_def, account_def, account_base_impl_def = contract_defs
    starknet = await Starknet.empty()

    account_base_impl_decl = await starknet.declare(
        contract_class=account_base_impl_def,
    )

    account_actual_impl = await starknet.declare(
        contract_class=account_def,
    )

    account1, call_info = await deploy_account_txn(
        starknet, signer, proxy_def, account_base_impl_decl, account_actual_impl
    )

    proxy = StarknetContract(
        state=starknet.state,
        abi=proxy_def.abi,
        contract_address=account1.contract_address,
        deploy_call_info=call_info,
    )

    account2, call_info = await deploy_account_txn(
        starknet, signer2, proxy_def, account_base_impl_decl, account_actual_impl
    )

    proxy2 = StarknetContract(
        state=starknet.state,
        abi=proxy_def.abi,
        contract_address=account2.contract_address,
        deploy_call_info=call_info,
    )

    return (starknet, account_actual_impl, account1, account2, proxy)


@pytest.mark.asyncio
async def test_constructor_sets_correct_implementation(proxy_init):
    _, declaration, _, _, proxy = proxy_init

    execution_info = await proxy.get_implementation().call()
    assert execution_info.result.implementation == declaration.class_hash


@pytest.mark.asyncio
async def test_initializer(proxy_init):
    _, _, account1, _, _ = proxy_init

    execution_info = await account1.get_public_key().call()
    assert execution_info.result.res == signer.public_key


@pytest.mark.asyncio
async def test_initializer_fails_when_already_init(proxy_init):
    _, _, _, account2, proxy = proxy_init

    await assert_revert(
        signer2.send_transaction(
            account2, proxy.contract_address, "initializer", [signer2.public_key]
        ),
        "Proxy: contract already initialized",
    )


@pytest.mark.asyncio
async def test_interface(proxy_init):
    _, _, account1, _, _ = proxy_init

    execution_info = await account1.supportsInterface(IACCOUNT_ID).call()
    assert execution_info.result.success == True


@pytest.mark.asyncio
async def test_fallback_when_selector_does_not_exist(proxy_init):
    _, _, account1, _, proxy = proxy_init

    await assert_revert(
        signer.send_transaction(account1, proxy.contract_address, "bad_selector", []),
        "not found in contract with class hash",
    )


@pytest.mark.asyncio
async def test_upgrade(proxy_init):
    starknet, declaration, account1, account2, proxy = proxy_init

    with open(
        file=contract_path("tests/aux/Braavos_Account_with_ver_111.111.111.json"),
        encoding="utf-8",
    ) as f:
        account_class_w_ver = ContractClass.loads(f.read())
        account_class_w_ver_decl = await starknet.declare(
            contract_class=account_class_w_ver,
        )

    # Verify only the the proxy admin (account1) can upgrade / migrate, by calling the proxy from another account
    await assert_revert(
        signer2.send_transaction(
            account2,
            proxy.contract_address,
            "upgrade",
            [account_class_w_ver_decl.class_hash],
        ),
        "Proxy: caller is not admin",
    )

    await assert_revert(
        signer2.send_transaction(
            account2, proxy.contract_address, "migrate_storage", [0]
        ),
        "Proxy: caller is not admin",
    )

    execution_info = await proxy.get_implementation().call()
    assert execution_info.result.implementation == declaration.class_hash

    # Upgrade
    tx_info = await signer.send_transaction(
        account1,
        proxy.contract_address,
        "upgrade",
        [account_class_w_ver_decl.class_hash],
    )

    assert_event_emitted(
        tx_info,
        from_address=proxy.contract_address,
        keys="Upgraded",
        data=[account_class_w_ver_decl.class_hash],
    )

    execution_info = await proxy.get_implementation().call()
    assert execution_info.result.implementation == account_class_w_ver_decl.class_hash

    account_after_upgrade = StarknetContract(
        state=starknet.state,
        abi=account_class_w_ver_decl.abi,
        contract_address=proxy.contract_address,
        deploy_call_info=proxy.deploy_call_info,
    )

    target_ver_felt = str_to_felt("111.111.111")
    execution_info = await account_after_upgrade.get_impl_version().call()
    assert execution_info.result.res == target_ver_felt

    storage_migration_var = await account_after_upgrade.state.state.get_storage_at(
        account_after_upgrade.contract_address,
        starknet_keccak(b"Account_storage_migration_version"),
    )
    assert storage_migration_var == target_ver_felt

    # Revert proxy back to code version of account so subsequent tests won't run on a proxy pointing to v 0x1111111 account
    await signer.send_transaction(
        account_after_upgrade,
        proxy.contract_address,
        "upgrade",
        [declaration.class_hash],
    )

    execution_info = await proxy.get_implementation().call()
    assert execution_info.result.implementation == declaration.class_hash

    execution_info = await account1.get_impl_version().call()
    assert execution_info.result.res == str_to_felt("000.000.009")


@pytest.mark.asyncio
async def test_upgrade_sn09_prior_mult_signers_upgrade_migrate_to_sn010_and_txns(
    contract_defs, proxy_init
):
    proxy_def, _, _ = contract_defs
    starknet, declaration, _, _, _ = proxy_init

    with open(
        file=contract_path("tests/aux/Braavos_Account_prior_mult_signers.json"),
        encoding="utf-8",
    ) as f:
        account_class_before_multi_signers = ContractClass.loads(f.read())
        account_class_before_multi_signers_decl = await starknet.declare(
            contract_class=account_class_before_multi_signers,
        )

    # Uses legacy deploy
    proxy_no_multi_signers = await starknet.deploy(
        contract_class=proxy_def,
        constructor_calldata=[
            account_class_before_multi_signers_decl.class_hash,
            get_selector_from_name("initializer"),
            1,
            signer.public_key,
        ],
    )

    account_no_multi_signers = StarknetContract(
        state=starknet.state,
        abi=account_class_before_multi_signers_decl.abi,
        contract_address=proxy_no_multi_signers.contract_address,
        deploy_call_info=proxy_no_multi_signers.deploy_call_info,
    )

    # Upgrade SN 0.9.X contract so we need to send txn v0
    tx_info = await signer.send_transactions_v0(
        account_no_multi_signers,
        [
            (
                proxy_no_multi_signers.contract_address,
                "upgrade",
                [declaration.class_hash],
            )
        ],
        nonce=0,
    )

    assert_event_emitted(
        tx_info,
        from_address=proxy_no_multi_signers.contract_address,
        keys="Upgraded",
        data=[declaration.class_hash],
    )

    execution_info = await proxy_no_multi_signers.get_implementation().call()
    assert execution_info.result.implementation == declaration.class_hash

    # Send a txn to check for public key migration to multi signers
    account_after_upgrade = StarknetContract(
        state=starknet.state,
        abi=declaration.abi,
        contract_address=proxy_no_multi_signers.contract_address,
        deploy_call_info=proxy_no_multi_signers.deploy_call_info,
    )
    # Before first txn we exepect @view functions to dry-run migrations themselves
    execution_info = await account_after_upgrade.get_execution_time_delay().call()
    assert execution_info.result.etd_sec == 345600

    execution_info = await account_after_upgrade.get_public_key().call()
    assert execution_info.result.res == signer.public_key

    hash = pedersen_hash(0x11111, 0x22222)
    sig_r, sig_s = signer.signer.sign(hash)
    execution_info = await account_after_upgrade.is_valid_signature(hash, [sig_r, sig_s]).call()
    assert execution_info.result.is_valid == 1

    # First txn will migrate the key
    response = await signer.send_transactions(
        account_after_upgrade,
        [(account_after_upgrade.contract_address, "get_public_key", [])],
    )
    assert response.call_info.retdata[1] == signer.public_key

    # And will also migrate ETD
    execution_info = await account_after_upgrade.get_execution_time_delay().call()
    assert execution_info.result.etd_sec != 0

    # Second txn will use the signer from the list and let's validate it
    # by sending with signer id (which must be 0) and parse the response
    response = await signer.send_transactions(
        account_after_upgrade,
        [(account_after_upgrade.contract_address, "get_signers", [])],
        signer_id=0,
    )

    # skip __execute__'s raw retdata at index 0 when parsing
    all_signers = parse_get_signers_response(response.call_info.retdata[1:])
    assert all_signers[0][5] == 1  # Type is STARK signer
    assert all_signers[0][0] == 0  # index is 0
    assert all_signers[0][1] == signer.public_key  # public key is correct


@pytest.mark.asyncio
async def test_upgrade_sn09_mult_signers_upgrade_migrate_to_sn010_and_txns(
    contract_defs, proxy_init
):
    proxy_def, _, _ = contract_defs
    starknet, declaration, _, _, _ = proxy_init

    with open(
        file=contract_path("tests/aux/Braavos_Account_sn09_with_mult_signers.json"),
        encoding="utf-8",
    ) as f:
        account_class_sn09_multi_signers = ContractClass.loads(f.read())
        account_class_sn_09_multi_signers_decl = await starknet.declare(
            contract_class=account_class_sn09_multi_signers,
        )

    # Uses legacy deploy
    proxy_multi_signers = await starknet.deploy(
        contract_class=proxy_def,
        constructor_calldata=[
            account_class_sn_09_multi_signers_decl.class_hash,
            get_selector_from_name("initializer"),
            1,
            signer.public_key,
        ],
    )

    account_multi_signers = StarknetContract(
        state=starknet.state,
        abi=account_class_sn_09_multi_signers_decl.abi,
        contract_address=proxy_multi_signers.contract_address,
        deploy_call_info=proxy_multi_signers.deploy_call_info,
    )

    # Upgrade SN 0.9.X contract so we need to send txn v0
    tx_info = await signer.send_transactions_v0(
        account_multi_signers,
        [(proxy_multi_signers.contract_address, "upgrade", [declaration.class_hash])],
        nonce=0,
    )

    assert_event_emitted(
        tx_info,
        from_address=proxy_multi_signers.contract_address,
        keys="Upgraded",
        data=[declaration.class_hash],
    )

    execution_info = await proxy_multi_signers.get_implementation().call()
    assert execution_info.result.implementation == declaration.class_hash

    # Send a txn to check for public key migration to multi signers
    account_after_upgrade = StarknetContract(
        state=starknet.state,
        abi=declaration.abi,
        contract_address=proxy_multi_signers.contract_address,
        deploy_call_info=proxy_multi_signers.deploy_call_info,
    )

    # Since it was a multi-signer contract, then we can use signer_id 0 directly
    # by sending with signer id (which must be 0) and parse the response
    response = await signer.send_transactions(
        account_after_upgrade,
        [(account_after_upgrade.contract_address, "get_signers", [])],
        signer_id=0,
    )

    # skip __execute__'s raw retdata at index 0 when parsing
    all_signers = parse_get_signers_response(response.call_info.retdata[1:])
    assert all_signers[0][5] == 1  # Type is STARK signer
    assert all_signers[0][0] == 0  # index is 0
    assert all_signers[0][1] == signer.public_key  # public key is correct


# TODO: verify we emit an event on key change (constructor + ?set_public_key?)
# TODO: add check for deploying a valid/non-valid account (i.e.: not IACCOUNT_ID)
