"""Framing without a socket: bytes in, complete frames out.

The receivers drive these functions through a real TCP connection in
`tests/integration/test_syslog_receiver.py`; testing the helpers directly is how
the split-frame and fallback cases stay cheap to pin.
"""

from __future__ import annotations

from opencanary_correlator.connectors.receivers._framing import (
    next_delimiter,
    split_delimited,
    split_octet_counted,
)


def test_a_frame_split_across_segments_waits_for_the_rest() -> None:
    buffer = bytearray(b'12 <134>{"a":1}')

    payloads, overflow, octet = split_octet_counted(buffer, max_bytes=1024)

    assert (payloads, overflow, octet) == ([b'<134>{"a":1}'], False, True)
    assert bytes(buffer) == b""

    # The next frame arrives in pieces: nothing is emitted until it is complete.
    buffer.extend(b"5 hel")
    assert split_octet_counted(buffer, max_bytes=1024) == ([], False, True)

    buffer.extend(b"lo")
    assert split_octet_counted(buffer, max_bytes=1024) == ([b"hello"], False, True)


def test_a_split_length_prefix_is_not_taken_for_a_message() -> None:
    buffer = bytearray(b"1")
    assert split_octet_counted(buffer, max_bytes=1024) == ([], False, True)

    buffer.extend(b'2 <134>{"a":1}')
    payloads, overflow, octet = split_octet_counted(buffer, max_bytes=1024)

    assert (payloads, overflow, octet) == ([b'<134>{"a":1}'], False, True)


def test_a_digit_leading_body_falls_back_to_newline_framing() -> None:
    """An ISO timestamp is a message, not a length prefix."""
    buffer = bytearray(b"2024-01-01T00:00:00Z host app: hello\n")

    payloads, overflow, octet = split_octet_counted(buffer, max_bytes=1024)

    assert (payloads, overflow, octet) == ([], False, False)
    # Nothing was consumed, so the newline splitter still sees the whole frame.
    assert split_delimited(buffer, max_bytes=1024) == (
        [b"2024-01-01T00:00:00Z host app: hello"],
        False,
    )


def test_an_oversized_octet_frame_is_reported_as_overflow() -> None:
    buffer = bytearray(b"99 hello\n")

    assert split_octet_counted(buffer, max_bytes=10) == ([], True, True)


def test_carriage_returns_are_stripped_from_delimited_frames() -> None:
    buffer = bytearray(b"one\r\ntwo\x00")

    payloads, overflow = split_delimited(buffer, max_bytes=1024)

    assert payloads == [b"one", b"two"]
    assert overflow is False
    assert bytes(buffer) == b""


def test_an_unterminated_line_over_the_limit_is_overflow() -> None:
    buffer = bytearray(b"x" * 11)

    assert split_delimited(buffer, max_bytes=10) == ([], True)


def test_the_first_delimiter_wins() -> None:
    assert next_delimiter(bytearray(b"a\x00b\nc")) == 1
    assert next_delimiter(bytearray(b"abc")) == -1
