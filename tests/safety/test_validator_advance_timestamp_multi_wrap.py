"""SafetyValidatorInstance.advance_timestamp must count every wrap.

Before this fix, advance_timestamp bumped rollover_count by exactly 1
even when the increment spanned multiple 16-bit wraps. An increment of
0x30000 would wrap three times but only tick rollover once, drifting
the Extended-format CRC seed away from the producer's.
"""
from __future__ import annotations

from ethernetip.safety.validator_object import SafetyValidatorInstance


def test_single_wrap_bumps_rollover_once():
    v = SafetyValidatorInstance(timestamp=0xFF00, rollover_count=5)
    v.advance_timestamp(0x0200)  # 0xFF00 + 0x0200 = 0x10100 → wraps once
    assert v.rollover_count == 6
    assert v.timestamp == 0x0100


def test_multi_wrap_bumps_rollover_by_wraps_count():
    v = SafetyValidatorInstance(timestamp=0x0000, rollover_count=0)
    v.advance_timestamp(0x30000)  # exactly 3 wraps, ts stays 0
    assert v.rollover_count == 3
    assert v.timestamp == 0


def test_multi_wrap_with_partial_tail():
    v = SafetyValidatorInstance(timestamp=0x8000, rollover_count=10)
    # 0x8000 + 0x28000 = 0x30000 → 3 wraps
    v.advance_timestamp(0x28000)
    assert v.rollover_count == 13
    assert v.timestamp == 0


def test_no_wrap_leaves_rollover_alone():
    v = SafetyValidatorInstance(timestamp=0x0100, rollover_count=7)
    v.advance_timestamp(0x0100)
    assert v.rollover_count == 7
    assert v.timestamp == 0x0200
