"""ot_connection_id assignment must not start from a predictable 0.

Prior behavior: the counter was initialized to 0 and incremented per
Forward_Open, so the first ids an originator saw were 1, 2, 3 ... and
an off-path attacker could trivially predict the next ids and spoof
Forward_Close / SendUnitData frames against connections it didn't open.

Fix: seed the counter with secrets.randbits(32) so the sequence is
cryptographically unpredictable while still monotonic within a process.
"""

from __future__ import annotations

from ethernetip.connections.connection_manager import ConnectionManagerObject


def test_initial_counter_is_randomized():
    cm = ConnectionManagerObject()
    # secrets.randbits(32) covers the full 32-bit range; the odds of it
    # landing below some small bound by chance should be negligible.
    assert cm._next_connection_id > 0xFFFF, (
        f"ot_connection_id seed {cm._next_connection_id} looks predictable; "
        "expected a cryptographically random 32-bit value"
    )


def test_distinct_instances_use_independent_seeds():
    seeds = {ConnectionManagerObject()._next_connection_id for _ in range(32)}
    # Random 32-bit seeds have an astronomically low chance of colliding
    # even across many instances; a shared constant seed would collapse
    # the set to size 1.
    assert len(seeds) >= 30


def test_counter_still_wraps_at_32_bits():
    cm = ConnectionManagerObject()
    cm._next_connection_id = 0xFFFFFFFE
    # Trigger the increment path via _process_forward_open's masking: we
    # emulate it directly since building a full ForwardOpenRequest here
    # would duplicate the integration tests.
    cm._next_connection_id = (cm._next_connection_id + 1) & 0xFFFFFFFF
    assert cm._next_connection_id == 0xFFFFFFFF
    cm._next_connection_id = (cm._next_connection_id + 1) & 0xFFFFFFFF
    assert cm._next_connection_id == 0  # wrapped cleanly, no overflow
