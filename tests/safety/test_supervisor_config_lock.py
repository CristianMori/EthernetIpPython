"""Configuration Lock gates mutating Safety Supervisor services.

Attribute 4 (Configuration Lock) on the Safety Supervisor (class
0x39, instance 1) non-zero means the configuration is frozen.
Propose_TUNID (0x56), Apply_TUNID (0x57) and Safety_Reset (0x54) must
refuse writes with Object State Conflict (0x0C) while the lock is
engaged.
"""
from __future__ import annotations

from ethernetip.cip.service import CipServiceRequest
from ethernetip.safety.supervisor_object import (
    SafetySupervisorObject,
    APPLY_TUNID_SERVICE, PROPOSE_TUNID_SERVICE, SAFETY_RESET_SERVICE,
)
from ethernetip.safety.types import SafetyNetworkNumber, UniqueNetworkId


def _make_supervisor() -> SafetySupervisorObject:
    sv = SafetySupervisorObject(
        SafetyNetworkNumber(b'\x01\x02\x03\x04\x05\x06'), 0xC0A80101)
    return sv


def _engage_lock(sv: SafetySupervisorObject) -> None:
    inst = sv.cip_class.get_instance(1)
    a4 = inst.get_attribute(4)
    a4.set_data(bytes([0x01]))


def _call(sv: SafetySupervisorObject, service: int, data: bytes):
    inst = sv.cip_class.get_instance(1)
    req = CipServiceRequest(service_code=service, path=b'', data=data)
    svc_def = sv.cip_class.get_instance_service(service)
    return svc_def.handler(inst, req)


def test_propose_tunid_refused_when_locked():
    sv = _make_supervisor()
    _engage_lock(sv)
    tunid = bytes(UniqueNetworkId.SIZE)
    resp = _call(sv, PROPOSE_TUNID_SERVICE, tunid)
    assert resp.status.general_status == 0x0C


def test_apply_tunid_refused_when_locked():
    sv = _make_supervisor()
    _engage_lock(sv)
    tunid = bytes(UniqueNetworkId.SIZE)
    resp = _call(sv, APPLY_TUNID_SERVICE, tunid)
    assert resp.status.general_status == 0x0C


def test_safety_reset_refused_when_locked():
    sv = _make_supervisor()
    _engage_lock(sv)
    resp = _call(sv, SAFETY_RESET_SERVICE, bytes([0x00]))
    assert resp.status.general_status == 0x0C


def test_propose_tunid_allowed_when_unlocked():
    """Baseline — the lock defaults to 0, so a Propose_TUNID succeeds."""
    sv = _make_supervisor()
    tunid = bytes(UniqueNetworkId.SIZE)
    resp = _call(sv, PROPOSE_TUNID_SERVICE, tunid)
    assert resp.status.is_success
