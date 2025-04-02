import e2e.utils.utils_v2 as utils_v2
from e2e.utils.utils_v2 import (
    TEST_HASH,
    TestSigner,
    MAX_EXECUTE_FEE_ETH,
    MAX_SIGN_FEE_ETH,
    MAX_EXECUTE_FEE_STRK,
    MAX_SIGN_FEE_STRK,
    TestSigner,
    check_pending_tx_event,
    STRK_ADDRESS,
    EXECUTION_RESOURCE_BOUNDS,
    SIGNER_RESOURCE_BOUNDS,
    HIGH_EXECUTION_RESOURCE_BOUNDS,
    HIGH_SIGNER_RESOURCE_BOUNDS,
)
from e2e.utils.fixtures import *
from e2e.utils.fixtures_moa import *
from e2e.utils.utils import (
    create_stark_signer,
    generate_secp256r1_keypair,
    create_secp256r1_signer,
    create_webauthn_signer,
    create_multisig_signer,
    flatten_seq,
)

import pytest
import random

from starknet_py.net.account.account import Account, KeyPair


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ["secp256r1_keypair", "is_webauthn", "multisig_threshold"],
    [
        (None, False, 0),
        (generate_secp256r1_keypair(), False, 0),
        (generate_secp256r1_keypair(), False, 2),
        (generate_secp256r1_keypair(), True, 0),
        (generate_secp256r1_keypair(), True, 2),
    ],
    ids=[
        "basic_stark_signer",
        "with_secp256r1_no_multisig",
        "with_secp256r1_multisig",
        "with_webauthn_no_multisig",
        "with_webauthn_multisig",
    ],
)
async def test_moa_signer_valid(
    prepare_simple_signer,
    account_deployer,
    secp256r1_keypair,
    is_webauthn,
    multisig_threshold,
):
    signer: TestSigner = prepare_simple_signer

    # create braavos account
    secp256r1_pubk = (None if secp256r1_keypair is None else flatten_seq(
        secp256r1_keypair[1]))
    stark_privk = random.randint(1, 10**10)
    braavos_account, _ = await account_deployer(
        stark_privk,
        secp256r1_pubk,
        multisig_threshold,
        is_webauthn=is_webauthn,
    )
    braavos_account: Account

    # add braavos account as a signer
    braavos_acc_pubkey = KeyPair.from_private_key(stark_privk).public_key
    calldata = [
        1,
        braavos_account.address,
        braavos_acc_pubkey,
        2,
    ]
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

    # check that 1 sig is not enough
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
    assert res[0] == utils_v2.NOT_ENOUGH_CONFIRMATIONS, "Signature should be invalid"

    # check that braavos account signature validated
    txn = utils_v2.txn_stub(TEST_HASH)
    stark_signer = create_stark_signer(stark_privk)
    stark_sig = stark_signer.sign_transaction(txn)
    if secp256r1_keypair is None:
        braavos_sig = stark_sig
    else:
        strong_signer = (create_webauthn_signer(secp256r1_keypair[0])
                         if is_webauthn else create_secp256r1_signer(
                             secp256r1_keypair[0]))
        if multisig_threshold == 0:
            braavos_sig = strong_signer.sign_transaction(txn)
        else:
            multisigner = create_multisig_signer(stark_signer, strong_signer)
            braavos_sig = multisigner.sign_transaction(txn)

    preamble_hash = utils_v2.calculate_preamble_hash(signer.account.address,
                                                     TEST_HASH, braavos_sig)
    braavos_pre_r, braavos_pre_s = message_signature(preamble_hash,
                                                     stark_privk)

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
            braavos_account.address,
            braavos_acc_pubkey,
            braavos_pre_r,
            braavos_pre_s,
            len(braavos_sig),
            *braavos_sig,
        ],
    )
    assert res[0] == utils_v2.VALID, "sig validation failed"
