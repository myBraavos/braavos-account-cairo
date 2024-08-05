from typing import List
import time
from starknet_py.hash.selector import get_selector_from_name
from starknet_py.hash.hash_method import HashMethod
from starknet_py.net.client_models import Call
from starknet_py.constants import FEE_CONTRACT_ADDRESS
from starknet_py.utils.iterable import ensure_iterable
from starknet_py.net.account.account import _parse_calls
from starknet_py.utils.typed_data import (TypedData, TypeContext)
from e2e.utils.utils import *
from e2e.utils.utils_v2 import *

STRK_ADDRESS = 0x04718F5A0FC34CC1AF16A1CDEE98FFB20C31F5CD61D6AB07201858F4287C938D


def get_test_call(address,
                  transfer_amount,
                  token_address=int(FEE_CONTRACT_ADDRESS, 16),
                  function_name="transfer",
                  is_high_amount=False):
    return Call(
        to_addr=token_address,
        selector=get_selector_from_name(function_name),
        calldata=[address, transfer_amount, 1 if is_high_amount else 0],
    )


def get_typed_data(message,
                   types,
                   primaryType,
                   domain_name,
                   domain_version="2",
                   domain_revision="1",
                   chain_id=hex(DEVNET_CHAIN_ID)):

    return TypedData.from_dict({
        "primaryType": primaryType,
        "types": {
            **types, "StarknetDomain": [{
                "name": "name",
                "type": "shortstring"
            }, {
                "name": "version",
                "type": "shortstring"
            }, {
                "name": "chainId",
                "type": "shortstring"
            }, {
                "name": "revision",
                "type": "shortstring"
            }]
        },
        "domain": {
            "name": domain_name,
            "version": domain_version,
            "chainId": chain_id,
            "revision": domain_revision
        },
        "message": message
    })


class OutsideExecution:

    def __init__(
        self,
        account,
        caller: int = int.from_bytes(b"ANY_CALLER", byteorder="big"),
        nonce=0,
        execute_after=time.time() - 1000,
        execute_before=time.time() + 1000,
        calls: List[Call] = [get_test_call(0x1, 1)],
    ):
        self.caller = caller
        self.nonce = nonce
        self.execute_after = int(execute_after)
        self.execute_before = int(execute_before)
        self.calls = calls
        self.sig = []

        self.typedData = get_typed_data(
            message={
                "Caller": self.caller,
                "Nonce": self.nonce,
                "Execute After": self.execute_after,
                "Execute Before": self.execute_before,
                "Calls":
                parse_calls_for_typed_data(ensure_iterable(self.calls))
            },
            primaryType="OutsideExecution",
            domain_name="Account.execute_from_outside",
            types={
                "OutsideExecution": [
                    {
                        "name": "Caller",
                        "type": "ContractAddress"
                    },
                    {
                        "name": "Nonce",
                        "type": "felt"
                    },
                    {
                        "name": "Execute After",
                        "type": "u128"
                    },
                    {
                        "name": "Execute Before",
                        "type": "u128"
                    },
                    {
                        "name": "Calls",
                        "type": "Call*"
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
                ]
            })

        self.sig = account.signer.sign_message(self.typedData, account.address)

    def get_serialized_calls(self):
        return _parse_calls(1, self.calls)

    def get_calldata(self):
        return [
            self.caller,
            self.nonce,
            self.execute_after,
            self.execute_before,
            *self.get_serialized_calls(),
            len(self.sig),
            *self.sig,
        ]

    def prepare_call(self, account_address):
        return Call(
            to_addr=account_address,
            selector=get_selector_from_name("execute_from_outside_v2"),
            calldata=self.get_calldata(),
        )


class SessionBase:

    def get_allowed_method_guids(self):
        return [
            self.get_allowed_method_guid(method)
            for method in self.allowed_methods
        ]

    def get_hash(self, account_address):
        x = self.typedData.message_hash(account_address)
        return x

    def get_spending_limit_calldata(self):
        return [
            len(self.spending_limits), *flatten_seq([[
                spending_limit["token_address"],
                spending_limit["amount"]['low'],
                spending_limit["amount"]['high']
            ] for spending_limit in self.spending_limits])
        ]

    def get_allowed_method_guid(self, allowed_method):
        type_hash = "AllowedMethod"
        return self.typedData._encode_value(type_hash, allowed_method)

    def get_allowed_methods_calldata(self):
        return [len(self.allowed_methods), *self.get_allowed_method_guids()]

    def get_allowed_methods_hint_calldata(self,
                                          calls,
                                          override_call_hints=None):
        if not override_call_hints is None:
            return [len(override_call_hints), *override_call_hints]

        guid_list = self.get_allowed_method_guids()
        l = [
            len(calls), *[
                guid_list.index(
                    self.get_allowed_method_guid({
                        "Contract Address": call.to_addr,
                        "Selector": hex(call.selector)
                    })) for call in calls
            ]
        ]
        return l


class GasSponsoredSessionExecution(SessionBase):

    def __init__(
        self,
        account: Account,
        caller,
        execute_after,
        execute_before,
        calls: List[Call],
        spending_limits,
    ):
        self.caller = caller
        self.execute_after = int(execute_after)
        self.execute_before = int(execute_before)

        self.sig = []

        self.allowed_methods = [{
            "Contract Address": method.to_addr,
            "Selector": hex(method.selector)
        } for method in calls]

        self.spending_limits = [{
            "token_address": limit[0],
            "amount": to_uint256_dict(limit[1])
        } for limit in spending_limits]

        self.typedData = get_typed_data(
            message={
                "Caller": self.caller,
                "Execute After": self.execute_after,
                "Execute Before": self.execute_before,
                "Allowed Methods": self.allowed_methods,
                "Spending Limits": self.spending_limits,
            },
            primaryType="GasSponsoredSessionExecution",
            domain_name="Account.execute_gs_session",
            types={
                "GasSponsoredSessionExecution": [
                    {
                        "name": "Caller",
                        "type": "ContractAddress"
                    },
                    {
                        "name": "Execute After",
                        "type": "timestamp"
                    },
                    {
                        "name": "Execute Before",
                        "type": "timestamp"
                    },
                    {
                        "name": "Allowed Methods",
                        "type": "AllowedMethod*",
                    },
                    {
                        "name": "Spending Limits",
                        "type": "TokenAmount*"
                    },
                ],
                "AllowedMethod": [
                    {
                        "name": "Contract Address",
                        "type": "ContractAddress"
                    },
                    {
                        "name": "Selector",
                        "type": "selector"
                    },
                ]
            })

        self.sig = account.signer.sign_message(self.typedData, account.address)

    def get_calldata(self, calls, override_call_hints=None):
        return [
            self.execute_after,
            self.execute_before,
            *self.get_allowed_methods_calldata(),
            *self.get_spending_limit_calldata(),
            *_parse_calls(1, calls),
            *self.get_allowed_methods_hint_calldata(calls,
                                                    override_call_hints),
            len(self.sig),
            *self.sig,
        ]

    def prepare_call(self, calls, account_address, override_call_hints=None):
        return Call(
            to_addr=account_address,
            selector=get_selector_from_name(
                "execute_gas_sponsored_session_tx"),
            calldata=self.get_calldata(calls, override_call_hints),
        )


def get_test_gas_sponsored_session_execution_object(
    account,
    caller,
    execute_before=time.time() + 1000,
    execute_after=time.time() - 1000,
    calls=[
        Call(to_addr=STRK_ADDRESS,
             selector=get_selector_from_name("approve"),
             calldata=[]),
        Call(
            to_addr=STRK_ADDRESS,
            selector=get_selector_from_name("test0"),
            calldata=[],
        ),
        Call(
            to_addr=STRK_ADDRESS,
            selector=get_selector_from_name("test1"),
            calldata=[],
        ),
        Call(
            to_addr=int(FEE_CONTRACT_ADDRESS, 16),
            selector=get_selector_from_name("test2"),
            calldata=[],
        ),
        Call(
            to_addr=int(FEE_CONTRACT_ADDRESS, 16),
            selector=get_selector_from_name("transfer"),
            calldata=[],
        ),
        Call(
            to_addr=int(FEE_CONTRACT_ADDRESS, 16),
            selector=get_selector_from_name("test3"),
            calldata=[],
        ),
    ],
    spending_limits=[[STRK_ADDRESS, 50 * 18**18],
                     [FEE_CONTRACT_ADDRESS, 50 * 18 * 18]]):

    return GasSponsoredSessionExecution(account=account,
                                        caller=caller,
                                        execute_before=execute_before,
                                        execute_after=execute_after,
                                        calls=calls,
                                        spending_limits=spending_limits)


class SessionExecution(SessionBase):

    def __init__(
        self,
        account: Account,
        owner_pub_key,
        execute_after,
        execute_before,
        strk_gas_limit,
        calls: List[Call],
        spending_limits,
    ):
        self.owner_pub_key = owner_pub_key
        self.execute_after = int(execute_after)
        self.execute_before = int(execute_before)
        self.strk_gas_limit = int(strk_gas_limit)

        self.allowed_methods = [{
            "Contract Address": method.to_addr,
            "Selector": hex(method.selector)
        } for method in calls]

        self.spending_limits = [{
            "token_address": limit[0],
            "amount": to_uint256_dict(limit[1])
        } for limit in spending_limits]

        self.typedData = get_typed_data(message={
            "Owner Public Key":
            self.owner_pub_key,
            "Execute After":
            self.execute_after,
            "Execute Before":
            self.execute_before,
            "STRK Gas Limit":
            strk_gas_limit,
            "Allowed Methods":
            self.allowed_methods,
            "Spending Limits":
            self.spending_limits,
        },
                                        primaryType="SessionExecution",
                                        domain_name="Account.execute_session",
                                        types={
                                            "SessionExecution": [{
                                                "name": "Owner Public Key",
                                                "type": "felt"
                                            }, {
                                                "name":
                                                "Execute After",
                                                "type":
                                                "timestamp"
                                            }, {
                                                "name":
                                                "Execute Before",
                                                "type":
                                                "timestamp"
                                            }, {
                                                "name": "STRK Gas Limit",
                                                "type": "u128"
                                            }, {
                                                "name":
                                                "Allowed Methods",
                                                "type":
                                                "AllowedMethod*",
                                            }, {
                                                "name":
                                                "Spending Limits",
                                                "type":
                                                "TokenAmount*"
                                            }],
                                            "AllowedMethod": [
                                                {
                                                    "name": "Contract Address",
                                                    "type": "ContractAddress"
                                                },
                                                {
                                                    "name": "Selector",
                                                    "type": "selector"
                                                },
                                            ],
                                        })
        self.sig = account.signer.sign_message(self.typedData, account.address)

    def get_calldata(self, calls, override_call_hints=None):
        return [
            self.owner_pub_key,
            self.execute_after,
            self.execute_before,
            *self.get_allowed_methods_calldata(),
            self.strk_gas_limit,
            *self.get_spending_limit_calldata(),
            *self.get_allowed_methods_hint_calldata(calls,
                                                    override_call_hints),
            len(self.sig),
            *self.sig,
        ]

    def prepare_call(self, calls, account_address, override_call_hints=None):
        return [
            Call(
                to_addr=account_address,
                selector=get_selector_from_name("session_execute"),
                calldata=self.get_calldata(calls, override_call_hints),
            ), *calls
        ]


def get_test_session_execution_object(
        account,
        owner_pub_key,
        execute_before=time.time() + 1000,
        execute_after=time.time() - 1000,
        calls=[
            Call(to_addr=STRK_ADDRESS,
                 selector=get_selector_from_name("approve"),
                 calldata=[]),
            Call(
                to_addr=STRK_ADDRESS,
                selector=get_selector_from_name("test0"),
                calldata=[],
            ),
            Call(
                to_addr=STRK_ADDRESS,
                selector=get_selector_from_name("test1"),
                calldata=[],
            ),
            Call(
                to_addr=int(FEE_CONTRACT_ADDRESS, 16),
                selector=get_selector_from_name("test2"),
                calldata=[],
            ),
            Call(
                to_addr=int(FEE_CONTRACT_ADDRESS, 16),
                selector=get_selector_from_name("transfer"),
                calldata=[],
            ),
            Call(
                to_addr=int(FEE_CONTRACT_ADDRESS, 16),
                selector=get_selector_from_name("test3"),
                calldata=[],
            ),
        ],
        spending_limits=[[STRK_ADDRESS, 50 * 18**18],
                         [FEE_CONTRACT_ADDRESS, 50 * 18**18]],
        strk_gas_limit=10**18):

    return SessionExecution(account=account,
                            owner_pub_key=owner_pub_key,
                            execute_before=execute_before,
                            execute_after=execute_after,
                            strk_gas_limit=strk_gas_limit,
                            calls=calls,
                            spending_limits=spending_limits)
