"""Device identity information for ListIdentity and the Identity CIP object (class 0x01)."""

from dataclasses import dataclass


CLASS_CODE = 0x01


@dataclass
class IdentityInfo:
    vendor_id: int = 0x0001
    device_type: int = 0x000C
    product_code: int = 0x0001
    major_revision: int = 1
    minor_revision: int = 0
    serial_number: int = 0xC0FFEE42
    product_name: str = "EthernetIP Virtual Device"
    status: int = 0x0000
