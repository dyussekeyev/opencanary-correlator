"""RFC 6587 framing, shared by every stream receiver.

Both framings mutate the caller's buffer in place: a protocol owns one buffer
per connection and a frame is removed only once it is complete, so a frame split
across TCP segments stays in the buffer until the rest arrives.

The functions are pure apart from that buffer, which is what makes the framing
testable without a socket: feed bytes in, look at the frames that came out.
"""

from __future__ import annotations

from typing import Final

#: An octet-counted length prefix is at most ten digits.
MAX_LENGTH_PREFIX: Final[int] = 10


def next_delimiter(buffer: bytearray) -> int:
    """Return the offset of the first frame delimiter, or -1.

    Newline-separated frames are the OpenCanary ``SocketJSONHandler`` format.
    NUL is also accepted because Python's ``SysLogHandler`` terminates TCP
    messages with ``\\x00`` instead of a newline.
    """
    newline = buffer.find(b"\n")
    nul = buffer.find(b"\x00")
    if newline < 0:
        return nul
    if nul < 0:
        return newline
    return min(newline, nul)


def split_delimited(buffer: bytearray, *, max_bytes: int) -> tuple[list[bytes], bool]:
    """Split the buffer into newline/NUL frames.

    Returns the payloads plus an ``overflow`` flag that tells the caller the peer
    exceeded the configured line limit.
    """
    payloads: list[bytes] = []
    while True:
        index = next_delimiter(buffer)
        if index < 0:
            break
        line = bytes(buffer[:index]).rstrip(b"\r")
        del buffer[: index + 1]
        if len(line) > max_bytes:
            return [], True
        payloads.append(line)
    if len(buffer) > max_bytes:
        return [], True
    return payloads, False


def split_octet_counted(buffer: bytearray, *, max_bytes: int) -> tuple[list[bytes], bool, bool]:
    """Split RFC 6587 octet-counted frames (``MSG-LEN SP SYSLOG-MSG``).

    Returns the payloads, the overflow flag and whether the buffer really looked
    octet-counted. That third value is what lets the syslog protocol fall back to
    newline framing: a message whose body happens to start with a digit is not a
    length prefix, and the caller must not commit to the wrong framing.
    """
    payloads: list[bytes] = []
    while True:
        space = buffer.find(b" ")
        if space < 0:
            if not buffer:
                return payloads, False, True
            if len(buffer) <= MAX_LENGTH_PREFIX and bytes(buffer).isdigit():
                return payloads, False, True
            return payloads, False, False
        prefix = bytes(buffer[:space])
        if space > MAX_LENGTH_PREFIX or not prefix.isdigit():
            return payloads, False, False
        length = int(prefix)
        if length > max_bytes:
            return [], True, True
        start = space + 1
        if len(buffer) < start + length:
            return payloads, False, True
        payloads.append(bytes(buffer[start : start + length]))
        del buffer[: start + length]


__all__ = ["MAX_LENGTH_PREFIX", "next_delimiter", "split_delimited", "split_octet_counted"]
