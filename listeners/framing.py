"""Length-prefixed message framing for the brain.sock inter-process bridge.

Unix domain sockets are byte streams with no message boundaries, so a single
read()/write() pair is not guaranteed to align with a single logical message.
Every message sent over brain.sock is prefixed with a 4-byte big-endian length
header so readers know exactly how many bytes to pull off the wire.
"""
import struct
import asyncio

HEADER_FORMAT = "!I"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # guard against bogus/oversized length headers


def pack_message(payload: bytes) -> bytes:
    """Prefix payload with its 4-byte big-endian length."""
    return struct.pack(HEADER_FORMAT, len(payload)) + payload


async def read_message(reader: asyncio.StreamReader) -> bytes:
    """Read one length-prefixed message from a StreamReader.

    Raises asyncio.IncompleteReadError if the stream closes mid-message, and
    ValueError if the declared length is absurd (protects against a corrupt
    or malicious header driving an unbounded read).
    """
    header = await reader.readexactly(HEADER_SIZE)
    (length,) = struct.unpack(HEADER_FORMAT, header)
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"declared message length {length} exceeds max {MAX_MESSAGE_SIZE}")
    return await reader.readexactly(length)
