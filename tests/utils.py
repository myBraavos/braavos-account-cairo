from collections import namedtuple
from functools import reduce
import math
from os import environ
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    Prehashed,
)

from nile.signer import Signer
from nile.core.types.utils import get_execute_calldata, get_invoke_hash
from starkware.cairo.common.hash_state import compute_hash_on_elements
from starkware.starknet.business_logic.execution.objects import (
    Event,
    TransactionExecutionInfo,
)
from starkware.starknet.business_logic.state.storage_domain import StorageDomain
from starkware.starknet.business_logic.transaction.objects import (
    InternalInvokeFunction,
    InternalDeployAccount,
)
from starkware.starknet.compiler.compile import compile_starknet_files
from starkware.starknet.core.os.contract_address import contract_address
from starkware.starknet.core.os.transaction_hash.transaction_hash import (
    TransactionHashPrefix,
    calculate_transaction_hash_common,
    calculate_deploy_account_transaction_hash,
)
from starkware.starknet.definitions import constants
from starkware.starknet.definitions.general_config import StarknetChainId
from starkware.starknet.public.abi import get_selector_from_name
from starkware.starkware_utils.error_handling import StarkException
from starkware.starknet.services.api.gateway.transaction import InvokeFunction
from starkware.starknet.services.utils.sequencer_api_utils import (
    InternalInvokeFunctionForSimulate,
)
from starkware.starknet.testing.starknet import StarknetContract


MAX_UINT256 = (2**128 - 1, 2**128 - 1)
INVALID_UINT256 = (MAX_UINT256[0] + 1, MAX_UINT256[1])
ZERO_ADDRESS = 0
TRUE = 1
FALSE = 0

TRANSACTION_VERSION = 1
EST_FEE_TRANSACTION_VERSION = 2**128 + 1
EMPTY_HW_SIGNER = [
    0,  # signer 0
    0,  # signer 1
    0,  # signer 2
    0,  # signer 3
    0,  # type
    0,  # reserved 0
    0,  # reserved 1
]


_root = Path(__file__).parent.parent


def contract_path(name):
    if name.startswith("tests/") or name.startswith("lib/"):
        return str(_root / name)
    else:
        return str(_root / "src" / name)


def str_to_felt(text):
    b_text = bytes(text, "ascii")
    return int.from_bytes(b_text, "big")


def felt_to_str(felt):
    b_felt = felt.to_bytes(31, "big")
    return b_felt.decode()


def uint(a):
    return (a, 0)


def to_uint(a):
    """Takes in value, returns uint256-ish tuple."""
    return (a & ((1 << 128) - 1), a >> 128)


def from_uint(uint):
    """Takes in uint256-ish tuple, returns value."""
    return uint[0] + (uint[1] << 128)


def add_uint(a, b):
    """Returns the sum of two uint256-ish tuples."""
    a = from_uint(a)
    b = from_uint(b)
    c = a + b
    return to_uint(c)


def sub_uint(a, b):
    """Returns the difference of two uint256-ish tuples."""
    a = from_uint(a)
    b = from_uint(b)
    c = a - b
    return to_uint(c)


def mul_uint(a, b):
    """Returns the product of two uint256-ish tuples."""
    a = from_uint(a)
    b = from_uint(b)
    c = a * b
    return to_uint(c)


def div_rem_uint(a, b):
    """Returns the quotient and remainder of two uint256-ish tuples."""
    a = from_uint(a)
    b = from_uint(b)
    c = math.trunc(a / b)
    m = a % b
    return (to_uint(c), to_uint(m))


async def assert_revert(fun, reverted_with=None):
    try:
        await fun
        assert False, f"expected exception {reverted_with}"
    except StarkException as err:
        if reverted_with is not None:
            assert reverted_with in err.message
    except Exception as e:
        assert False, f"unexpected exception: {e}"


def assert_event_emitted(tx_exec_info, from_address, keys, data):
    assert (
        Event(
            from_address=from_address,
            keys=keys if isinstance(keys, list) else [get_selector_from_name(keys)],
            data=data,
        )
        in tx_exec_info.call_info.get_sorted_events()
    )


def assert_event_emitted_in_call_info(call_info, from_address, keys, data):
    assert (
        Event(
            from_address=from_address,
            keys=keys if isinstance(keys, list) else [get_selector_from_name(keys)],
            data=data,
        )
        in call_info.get_sorted_events()
    )


def get_contract_def(path):
    """Returns the contract definition from the contract path"""
    path = contract_path(path)
    contract_def = compile_starknet_files(
        files=[path],
        debug_info=True,
        disable_hint_validation=False,
        cairo_path=environ.get("CAIRO_PATH").split(":")
        if environ.get("CAIRO_PATH")
        else None,
    )
    return contract_def


def flatten_seq(x):
    return reduce(
        lambda target, elem: (target + flatten_seq(elem))
        if hasattr(elem, "__iter__") and not isinstance(elem, str)
        else (target + [elem] if isinstance(elem, int) else target + [int(elem, 16)]),
        x,
        [],
    )


INDEXED_SIGNER_STRUCT_SIZE = 8


def parse_get_signers_response(get_signers_response_array):
    num_signers = get_signers_response_array[0]
    all_signers = []
    for i in range(num_signers):
        offset = i * INDEXED_SIGNER_STRUCT_SIZE + 1
        all_signers.append(
            get_signers_response_array[offset : offset + INDEXED_SIGNER_STRUCT_SIZE]
        )
    return all_signers


async def deploy_account_txn(
    starknet,
    stark_signer,
    proxy_def,
    proxy_decl,
    account_base_impl,
    account_actual_impl,
    hw_signer=None,
    salt=None,
):
    salt = salt or stark_signer.public_key

    deploy_account_txn_ctor_calldata = [
        account_base_impl.class_hash,
        get_selector_from_name("initializer"),
        1,
        stark_signer.public_key,
    ]

    deploy_account_contract_address = contract_address.calculate_contract_address(
        salt=salt,
        contract_class=proxy_def,
        constructor_calldata=deploy_account_txn_ctor_calldata,
        deployer_address=0,
    )

    deploy_account_txn_hash = calculate_deploy_account_transaction_hash(
        version=TRANSACTION_VERSION,
        contract_address=deploy_account_contract_address,
        class_hash=proxy_decl.class_hash,
        constructor_calldata=deploy_account_txn_ctor_calldata,
        max_fee=0,
        nonce=0,
        salt=salt,
        chain_id=StarknetChainId.TESTNET.value,
    )

    enriched_deploy_account_txn_hash = compute_hash_on_elements(
        [
            deploy_account_txn_hash,
            account_actual_impl.class_hash if account_actual_impl != None else 0,
            *(hw_signer if hw_signer != None else EMPTY_HW_SIGNER),
        ]
    )

    deploy_account_txn_sig = stark_signer.signer.sign(enriched_deploy_account_txn_hash)
    sig = [
        *deploy_account_txn_sig,
        account_actual_impl.class_hash if account_actual_impl != None else 0,
        *(hw_signer if hw_signer != None else EMPTY_HW_SIGNER),
    ]

    deploy_account_txn = await InternalDeployAccount.create_for_testing(
        contract_class=proxy_def,
        contract_address_salt=salt,
        constructor_calldata=deploy_account_txn_ctor_calldata,
        max_fee=0,
        chain_id=StarknetChainId.TESTNET.value,
        signature=sig,
    )

    res = await starknet.state.execute_tx(tx=deploy_account_txn)

    return (
        StarknetContract(
            state=starknet.state,
            abi=account_actual_impl.abi
            if account_actual_impl != None
            else account_base_impl.abi,
            contract_address=deploy_account_contract_address,
            constructor_call_info=res.call_info,
        ),
        res.call_info,
    )


def create_ext_signer_wrapper(
        signer_id,
        ext_stark_signer,
        ext_hws_signer=None,
        ext_hws_signer_id=None,
        invalid_sig=False,
):
    hash_mod = 1 if invalid_sig else 0
    return namedtuple('SignerWrapper', ['sign'])(lambda hash: [
        signer_id,
        *ext_stark_signer.sign(hash),
        signer_id,
        *([5] if ext_hws_signer else [3]),
        *([ext_hws_signer_id] if ext_hws_signer else [0]),
        *(ext_hws_signer.sign(hash + hash_mod) if ext_hws_signer else ext_stark_signer.sign(hash + hash_mod)),
    ])


def create_raw_txn_with_fee_validation(account, entrypoint, calldata, max_fee):
    return [
        2,
        account.contract_address,
        get_selector_from_name("assert_expected_max_fee"),
        0,
        1,
        account.contract_address,
        get_selector_from_name(entrypoint),
        1,
        len(calldata),
        len(calldata) + 1,
        max_fee,
        *calldata
    ] if max_fee is not None else [
        1,
        account.contract_address,
        get_selector_from_name(entrypoint),
        0,
        len(calldata),
        len(calldata),
        *calldata,
    ]


def create_sign_pending_multisig_txn_call_from_original_call(
        account,
        orig_raw_calldata,
        orig_nonce,
        orig_max_fee = 0,
):
    # populate according to sign_pending_multisig_transaction api
    raw_calldata = [
        len(orig_raw_calldata),     # calldata_len
        *orig_raw_calldata,         # calldata
        orig_nonce,                 # pending nonce
        orig_max_fee,                          # pending max fee
        1,                          # pending txn ver
    ]
    return [
        1,
        account.contract_address,
        get_selector_from_name("sign_pending_multisig_transaction"),
        0,
        len(raw_calldata),
        len(raw_calldata),
        *raw_calldata,
    ]


async def send_raw_invoke(
    account,
    selector,
    calldata,
    max_fee=0,
    version=constants.TRANSACTION_VERSION,
    nonce=None,
    chain_id=StarknetChainId.TESTNET.value,
    signature=None,
    signer=None,
) -> TransactionExecutionInfo:
    starknet_state = account.state

    if version == 0:
        assert not nonce, "Nonce should be a part of calldata in txn v0"
    else:
        nonce = nonce or (
            await starknet_state.state.get_nonce_at(
                StorageDomain.ON_CHAIN,
                account.contract_address,
            )
        )

    if not signature:
        tx_hash = calculate_transaction_hash_common(
            TransactionHashPrefix.INVOKE,
            version,
            account.contract_address,
            0,
            calldata,
            max_fee,
            chain_id,
            [nonce] if nonce != None else [],
        )
        signature = signer.sign(tx_hash)

    # Patch allow any version for testing
    InternalInvokeFunction.verify_version = lambda _: True
    tx = InternalInvokeFunction.create(
        sender_address=account.contract_address,
        entry_point_selector=selector,
        calldata=calldata,
        max_fee=max_fee,
        version=version,
        signature=list(signature),
        nonce=nonce,
        chain_id=chain_id,
    )
    return await starknet_state.execute_tx(tx=tx)


class TestECCSigner:
    def __init__(self, private_key=None):
        if private_key == None:
            self.ecc_key = ec.generate_private_key(ec.SECP256R1())
            self.pk_x_uint256 = to_uint(self.ecc_key.public_key().public_numbers().x)
            self.pk_y_uint256 = to_uint(self.ecc_key.public_key().public_numbers().y)
        else:
            raise "TestECCSginer does not yet support user-supplied private key"

    async def send_transactions(self, account, signer_id, calls, nonce=None, max_fee=0):
        starknet_state = account.state
        if nonce is None:
            nonce = await starknet_state.state.get_nonce_at(
                StorageDomain.ON_CHAIN,
                account.contract_address,
            )

        execute_calldata = get_execute_calldata(calls)
        message_hash = get_invoke_hash(
            account.contract_address,
            execute_calldata,
            int(max_fee),
            nonce,
            TRANSACTION_VERSION,
            StarknetChainId.TESTNET.value,
        )
        sig = [signer_id, *self.sign(message_hash)]
        return await send_raw_invoke(
            account,
            get_selector_from_name("__execute__"),
            execute_calldata,
            signature=sig,
        )

    def sign(self, message_hash):
        message_hash_bytes = message_hash.to_bytes(
            (message_hash.bit_length() + 7) // 8, byteorder="big", signed=False
        )
        sig = self.ecc_key.sign(
            message_hash_bytes,
            ec.ECDSA(Prehashed(hashes.SHAKE256(len(message_hash_bytes)))),
        )
        r, s = decode_dss_signature(sig)
        return [*to_uint(r), *to_uint(s)]

class TestSigner:
    def __init__(self, private_key):
        self.signer = Signer(private_key)
        self.public_key = self.signer.public_key

    async def send_transaction(
        self, account, to, selector_name, calldata, nonce=None, max_fee=0
    ):
        return await self.send_transactions(
            account, [(to, selector_name, calldata)], nonce, max_fee
        )

    async def send_transactions(
        self, account, calls, nonce=None, max_fee=0, signer_id=None
    ):
        starknet_state = account.state
        if nonce is None:
            nonce = await starknet_state.state.get_nonce_at(
                StorageDomain.ON_CHAIN,
                account.contract_address,
            )

        (execute_calldata, sig_r, sig_s) = self.signer.sign_invoke(
            account.contract_address, calls, nonce, max_fee
        )
        # Use raw invoke until updating cairo-nile to support v0.10.1
        return await self.send_raw_invoke(
            account,
            get_selector_from_name("__execute__"),
            execute_calldata,
            nonce=nonce,
            signature=[*([signer_id] if signer_id else []), sig_r, sig_s],
        )

    async def send_transactions_v0(self, account, calls, nonce=None, max_fee=0):
        execute_calldata = [
            *get_execute_calldata(calls),
            *([nonce] if nonce != None else []),
        ]
        execute_selector = get_selector_from_name("__execute__")
        tx_hash = calculate_transaction_hash_common(
            TransactionHashPrefix.INVOKE,
            0,
            account.contract_address,
            execute_selector,
            execute_calldata,
            max_fee,
            StarknetChainId.TESTNET.value,
            [],
        )

        (sig_r, sig_s) = self.signer.sign(tx_hash)

        return await self.send_raw_invoke(
            account,
            execute_selector,
            execute_calldata,
            version=0,
            nonce=None,
            signature=[sig_r, sig_s],
        )

    async def send_raw_invoke(
        self,
        account,
        selector,
        calldata,
        max_fee=0,
        version=constants.TRANSACTION_VERSION,
        nonce=None,
        chain_id=StarknetChainId.TESTNET.value,
        signature=None,
    ) -> TransactionExecutionInfo:
        starknet_state = account.state

        if version == 0:
            assert not nonce, "Nonce should be a part of calldata in txn v0"
        else:
            nonce = nonce or (
                await starknet_state.state.get_nonce_at(
                    StorageDomain.ON_CHAIN,
                    account.contract_address,
                )
            )

        if signature:
            (sig_r, sig_s) = signature
        else:
            tx_hash = calculate_transaction_hash_common(
                TransactionHashPrefix.INVOKE,
                version,
                account.contract_address,
                0,
                calldata,
                max_fee,
                chain_id,
                [nonce] if nonce != None else [],
            )
            (sig_r, sig_s) = self.signer.sign(tx_hash)

        tx = InternalInvokeFunction.create(
            sender_address=account.contract_address,
            entry_point_selector=selector,
            calldata=calldata,
            max_fee=0,
            version=version,
            signature=[sig_r, sig_s],
            nonce=nonce,
            chain_id=chain_id,
        )
        return await starknet_state.execute_tx(tx=tx)

    async def estimate_fee(
        self, account, calls, nonce=None, max_fee=0
    ) -> TransactionExecutionInfo:
        starknet_state = account.state
        if nonce is None:
            nonce = await starknet_state.state.get_nonce_at(
                StorageDomain.ON_CHAIN,    
                account.contract_address,
            )

        execute_calldata = get_execute_calldata(calls)
        txn_hash = calculate_transaction_hash_common(
            TransactionHashPrefix.INVOKE,
            EST_FEE_TRANSACTION_VERSION,
            account.contract_address,
            0,
            execute_calldata,
            max_fee,
            StarknetChainId.TESTNET.value,
            [nonce],
        )

        (sig_r, sig_s) = self.signer.sign(txn_hash)
        InternalInvokeFunction.verify_version = lambda _: True
        internal_tx = InternalInvokeFunctionForSimulate.from_external(
            InvokeFunction(
                sender_address=account.contract_address,
                calldata=execute_calldata,
                version=EST_FEE_TRANSACTION_VERSION,
                max_fee=0,
                signature=[sig_r, sig_s],
                nonce=nonce,
            ),
            starknet_state.general_config,
        )

        execution_info = await internal_tx.apply_state_updates(
            # pylint: disable=protected-access
            starknet_state.state._copy(),
            starknet_state.general_config,
        )
        return execution_info.actual_resources
