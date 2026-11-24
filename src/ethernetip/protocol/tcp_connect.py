"""Bounded TCP connect shared by the EtherNet/IP clients."""
import asyncio


async def open_connection_bounded(host: str, port: int,
                                  connect_timeout: float | None):
    """asyncio.open_connection with an upper bound on the TCP handshake.

    connect_timeout — seconds (None disables). On expiry the pending connect
    is cancelled (asyncio closes the half-open socket) and TimeoutError is
    raised. Refused / unreachable errors propagate unchanged.
    """
    try:
        return await asyncio.wait_for(asyncio.open_connection(host, port),
                                      connect_timeout)
    except asyncio.TimeoutError:
        # asyncio.TimeoutError is not the builtin before Python 3.11.
        raise TimeoutError(
            f"TCP connect to {host}:{port} timed out after {connect_timeout} s"
        ) from None
