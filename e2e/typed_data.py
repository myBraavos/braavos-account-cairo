from starknet_py.utils.typed_data import (
    get_hex,
    encode_shortstring,
    is_pointer,
    strip_pointer,
    cast,
)
from poseidon_py.poseidon_hash import poseidon_hash_many
from starknet_py.net.models.chains import StarknetChainId
from typing import List, Union
from starknet_py.hash.selector import get_selector_from_name


class TypedDataR1:
    def __init__(self, types):
        self.types = {
            "StarknetDomain": [
                {"name": "name", "type": "shortstring"},
                {"name": "version", "type": "shortstring"},
                {"name": "chainId", "type": "shortstring"},
                {"name": "revision", "type": "shortstring"},
            ],
            **types,
        }
        self.domain = {
            "name": "Account.execute_from_outside",
            "version": "2",
            "chainId": StarknetChainId.TESTNET,
            "revision": "1",
        }

    def get_hash(self, message, account_address):
        message_struct = [
            encode_shortstring("StarkNet Message"),
            self.struct_hash("StarknetDomain", self.domain),
            account_address,
            self.struct_hash("OutsideExecution", message),
        ]
        return poseidon_hash_many(message_struct)

    def struct_hash(self, type_name, data):
        return poseidon_hash_many(
            [self.type_hash(type_name), *self._encode_data(type_name, data)]
        )

    def _get_dependencies(self, type_name: str) -> List[str]:
        if type_name not in self.types:
            # type_name is a primitive type, has no dependencies
            return []

        dependencies = set()

        def collect_deps(type_name: str) -> None:
            for param in self.types[type_name]:
                fixed_type = strip_pointer(param["type"])
                if fixed_type in self.types and fixed_type not in dependencies:
                    dependencies.add(fixed_type)
                    # recursive call
                    collect_deps(fixed_type)

        # collect dependencies into a set
        collect_deps(type_name)
        return [type_name, *list(dependencies)]

    def type_hash(self, type_name: str) -> int:
        return get_selector_from_name(self._encode_type(type_name))

    def _encode_type(self, type_name: str) -> str:
        primary, *dependencies = self._get_dependencies(type_name)
        types = [primary, *sorted(dependencies)]

        def make_dependency_str(dependency):
            lst = [f"\"{t['name']}\":\"{t['type']}\"" for t in self.types[dependency]]
            return f"\"{dependency}\"({','.join(lst)})"

        return "".join([make_dependency_str(x) for x in types])

    def _encode_data(self, type_name: str, data: dict) -> List[int]:
        values = []
        for param in self.types[type_name]:
            encoded_value = self._encode_value(param["type"], data[param["name"]])
            values.append(encoded_value)

        return values

    def _is_struct(self, type_name: str) -> bool:
        return type_name in self.types

    def _encode_value(self, type_name: str, value: Union[int, str, dict, list]) -> int:
        if is_pointer(type_name) and isinstance(value, list):
            type_name = strip_pointer(type_name)

            if self._is_struct(type_name):
                return poseidon_hash_many(
                    [self.struct_hash(type_name, data) for data in value]
                )
            return poseidon_hash_many([int(get_hex(val), 16) for val in value])

        if self._is_struct(type_name) and isinstance(value, dict):
            return self.struct_hash(type_name, value)

        value = cast(Union[int, str], value)
        return int(get_hex(value), 16)
