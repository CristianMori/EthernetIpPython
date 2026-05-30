"""CIP Safety CRC check-value tests — ported from C# SafetyCrcTests."""
import pytest
from ethernetip.safety.crc import SafetyCrc

CHECK_INPUT = b'123456789'


def test_s1_check_value():
    assert SafetyCrc.compute_s1(CHECK_INPUT, 0xFF) == 0x4C


def test_s2_check_value():
    assert SafetyCrc.compute_s2(CHECK_INPUT, 0xFF) == 0xBF


def test_s3_check_value():
    assert SafetyCrc.compute_s3(CHECK_INPUT, 0xFFFF) == 0x9516


def test_s4_check_value():
    # init=0xFFFFFFFF, no final XOR → 0x340BC6D9 for "123456789"
    assert SafetyCrc.compute_s4(CHECK_INPUT) == 0x340BC6D9


def test_s1_empty():
    assert SafetyCrc.compute_s1(b'', 0x00) == 0x00


def test_s1_single_byte():
    assert SafetyCrc.compute_s1(b'\x00', 0x00) == 0x00
    assert SafetyCrc.compute_s1(b'\x01', 0x00) == 0x37  # table[1]


def test_s3_single_byte_matches_ref():
    via_int = SafetyCrc.compute_s3(0xE0, 0xFFFF)
    via_bytes = SafetyCrc.compute_s3(b'\xe0', 0xFFFF)
    assert via_int == via_bytes


def test_s3_two_bytes_le_matches_ref():
    via_uint = SafetyCrc.compute_s3(0x1234, 0xFFFF)
    via_bytes = SafetyCrc.compute_s3(b'\x34\x12', 0xFFFF)
    assert via_uint == via_bytes


def test_s1_incremental():
    data = b'\x01\x02\x03\x04'
    all_at_once = SafetyCrc.compute_s1(data, 0xFF)
    part1 = SafetyCrc.compute_s1(data[:2], 0xFF)
    part2 = SafetyCrc.compute_s1(data[2:], part1)
    assert part2 == all_at_once


def test_s3_incremental():
    data = b'\x01\x02\x03\x04'
    all_at_once = SafetyCrc.compute_s3(data, 0xFFFF)
    part1 = SafetyCrc.compute_s3(data[:2], 0xFFFF)
    part2 = SafetyCrc.compute_s3(data[2:], part1)
    assert part2 == all_at_once


def test_pid_cid_seed_s1_nonzero():
    assert SafetyCrc.pid_cid_seed_s1(0x0001, 0x12345678, 0x0001) != 0


def test_pid_cid_seed_s3_nonzero():
    assert SafetyCrc.pid_cid_seed_s3(0x0001, 0x12345678, 0x0001) != 0


def test_pid_cid_seed_s5_nonzero():
    assert SafetyCrc.pid_cid_seed_s5(0x0001, 0x12345678, 0x0001) != 0


def test_pid_rollover_seed_s3_changes_with_rollover():
    pid = SafetyCrc.pid_cid_seed_s3(0x0001, 0x12345678, 0x0001)
    assert SafetyCrc.pid_rollover_seed_s3(0, pid) != SafetyCrc.pid_rollover_seed_s3(1, pid)


def test_pid_rollover_seed_s5_changes_with_rollover():
    pid = SafetyCrc.pid_cid_seed_s5(0x0001, 0x12345678, 0x0001)
    assert SafetyCrc.pid_rollover_seed_s5(0, pid) != SafetyCrc.pid_rollover_seed_s5(1, pid)
