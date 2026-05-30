"""CIP Assembly Object (Class 0x04) — I/O data buffers."""

from __future__ import annotations
import struct
import threading
from typing import Callable

from ..cip.cip_class import CipClass
from ..cip.attribute import CipAttribute, AttributeAccess
from ..cip.data_types import CipDataType

CLASS_CODE = 0x04
DATA_ATTRIBUTE_ID = 3


class AssemblyInstance:
    """An assembly instance holding a byte buffer for I/O data."""

    def __init__(self, instance_id: int, data_size: int, name: str | None = None):
        self.instance_id = instance_id
        self.data_size = data_size
        self.name = name
        self._data = bytearray(data_size)
        self._lock = threading.Lock()
        self.on_data_changed: list[Callable[[int, bytes], None]] = []

    def get_data(self) -> bytes:
        return bytes(self._data)

    def copy_data_to(self, dst: bytearray, offset: int = 0) -> None:
        dst[offset:offset + self.data_size] = self._data

    def set_data(self, source: bytes | bytearray | memoryview) -> None:
        with self._lock:
            n = min(len(source), self.data_size)
            self._data[:n] = source[:n]
        self._fire_data_changed()

    def write_dint(self, offset: int, value: int) -> None:
        with self._lock:
            struct.pack_into('<i', self._data, offset, value)
        self._fire_data_changed()

    def read_dint(self, offset: int = 0) -> int:
        return struct.unpack_from('<i', self._data, offset)[0]

    def write_bytes(self, offset: int, data: bytes) -> None:
        with self._lock:
            self._data[offset:offset + len(data)] = data
        self._fire_data_changed()

    @property
    def raw_buffer(self) -> bytearray:
        return self._data

    def _fire_data_changed(self) -> None:
        snapshot = bytes(self._data)
        for cb in self.on_data_changed:
            cb(self.instance_id, snapshot)


class AssemblyDataAttribute(CipAttribute):
    """CipAttribute backed directly by an AssemblyInstance's live buffer."""

    def __init__(self, assembly: AssemblyInstance):
        super().__init__(DATA_ATTRIBUTE_ID, CipDataType.BYTE,
                         AttributeAccess.GET_SINGLE | AttributeAccess.SET_SINGLE | AttributeAccess.GET_ALL,
                         assembly.raw_buffer)


class AssemblyObject:
    """CIP Assembly class managing I/O data buffer instances."""

    def __init__(self):
        self._cip_class = CipClass(CLASS_CODE, "Assembly", revision=2)
        self._cip_class.add_standard_instance_services()
        self._assemblies: dict[int, AssemblyInstance] = {}

    @property
    def cip_class(self) -> CipClass:
        return self._cip_class

    @property
    def assemblies(self) -> dict[int, AssemblyInstance]:
        return self._assemblies

    def add_instance(self, instance_id: int, data_size: int, name: str | None = None) -> AssemblyInstance:
        assembly = AssemblyInstance(instance_id, data_size, name)
        self._assemblies[instance_id] = assembly

        inst = self._cip_class.create_instance(instance_id)
        inst.add_attribute(CipAttribute.create_uint(1, CipDataType.UINT, AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, 0))
        inst.add_attribute(CipAttribute(2, CipDataType.UINT, AttributeAccess.GET_SINGLE, b''))
        inst.add_attribute(AssemblyDataAttribute(assembly))
        inst.add_attribute(CipAttribute.create_uint(4, CipDataType.UINT, AttributeAccess.GET_SINGLE | AttributeAccess.GET_ALL, data_size))
        inst.user_data = assembly
        return assembly

    def get_assembly(self, instance_id: int) -> AssemblyInstance | None:
        return self._assemblies.get(instance_id)
