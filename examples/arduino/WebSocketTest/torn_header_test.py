#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later
#
# torn_header_test.py -- TCP-level frame-tearing test client for WebSocketTest.ino
#
# WebSocketTest.ino exercises the AsyncWebSocket *send* path (server -> client)
# and is happily driven by a browser or `websocat`. This script exercises the
# *receive* path instead: AsyncWebSocketClient::_onData()'s header-parsing
# state machine (AwsParseState in src/AsyncWebSocket.cpp), specifically its
# handling of a WS frame header that is torn across TCP write/segment
# boundaries.
#
# No browser or off-the-shelf WS client library can drive this: they all hand
# a complete frame to the OS and let TCP decide how to packetize it. To force
# a header to arrive in two (or more) separate reads on the server, the test
# client has to own the raw socket and choose exactly how many bytes go out
# in each send() call. Hence: stdlib `socket` only, no dependencies.
#
# Each case opens its own connection, performs the HTTP Upgrade handshake,
# sends one deliberately torn (or otherwise malformed) frame, then checks
# that the device is still alive via a plain HTTP GET /clients on a fresh
# connection. Liveness-after-malformed-input is the practical oracle available
# from outside the device; it will catch a crash, reboot, or hang, but NOT a
# quiet memory-safety bug that doesn't immediately crash. For that, run this
# against a build with async_ws_log_v enabled (watch the serial log for the
# per-byte _pstate trace) and, if possible, under ASan/UBSan on a POSIX/host
# build of the same parser.
#
# Usage:
#   python3 torn_header_test.py --host 192.168.4.1
#   python3 torn_header_test.py --host 192.168.4.1 --case safari_close_no_mask
#   python3 torn_header_test.py --host 192.168.4.1 --list
#
import argparse
import base64
import collections
import hashlib
import http.client
import os
import random
import socket
import struct
import sys
import threading
import time

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OPCODE_CONT = 0x0
OPCODE_TEXT = 0x1
OPCODE_BIN = 0x2
OPCODE_CLOSE = 0x8
OPCODE_PING = 0x9
OPCODE_PONG = 0xA
OPCODE_RESERVED_CONTROL = 0xB  # undefined control opcode (0xB-0xF): must be rejected, RFC 6455 5.5

# AwsCloseCode values we expect the server to send back for each violation
# (src/AsyncWebSocket.h), so tests can check *which* error was reported, not
# just that the connection survived.
WS_CLOSE_NORMAL = 1000
WS_CLOSE_PROTOCOL_ERROR = 1002
WS_CLOSE_INTERNAL_ERROR = 1011


# ---------------------------------------------------------------------------
# Frame construction
# ---------------------------------------------------------------------------


def build_frame(opcode, payload=b"", fin=True, mask=True, len_form=None, declared_len=None):
    """Build a raw WS frame, with full control over the header so we can
    construct deliberately mismatched/oversized-length or forced-length-form
    frames that a normal client library would never produce.

    len_form: force '7', '16', or '64' bit length encoding regardless of
              payload size (None = pick the minimal form automatically).
    declared_len: put a different length in the header than len(payload)
                  actually sent -- used to test the extended-length /
                  truncation paths without sending gigabytes of data.

    Returns (frame_bytes, header_len) where header_len is the offset of the
    first payload byte -- i.e. every interesting "tear point" is in
    [1, header_len).
    """
    n = len(payload) if declared_len is None else declared_len
    if len_form is None:
        if n <= 125:
            len_form = "7"
        elif n <= 0xFFFF:
            len_form = "16"
        else:
            len_form = "64"

    b0 = (0x80 if fin else 0) | (opcode & 0x0F)
    hdr = bytearray([b0])

    mask_bit = 0x80 if mask else 0x00
    if len_form == "7":
        hdr.append(mask_bit | (n & 0x7F))
    elif len_form == "16":
        hdr.append(mask_bit | 126)
        hdr += struct.pack(">H", n & 0xFFFF)
    else:
        hdr.append(mask_bit | 127)
        hdr += struct.pack(">Q", n & 0xFFFFFFFFFFFFFFFF)

    header_len = len(hdr)
    if mask:
        key = bytes(random.randrange(256) for _ in range(4))
        hdr += key
        header_len += 4
        body = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    else:
        body = payload

    return bytes(hdr) + body, header_len


def build_close_payload(code, reason=b""):
    return struct.pack(">H", code) + reason


# ---------------------------------------------------------------------------
# Transport helpers
# ---------------------------------------------------------------------------


def ws_handshake(sock, host, path):
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode()
    sock.sendall(req)

    resp = b""
    sock.settimeout(5)
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(1024)
        if not chunk:
            raise ConnectionError("handshake: connection closed before headers completed")
        resp += chunk

    status_line = resp.split(b"\r\n", 1)[0]
    if b" 101 " not in status_line:
        raise ConnectionError(f"handshake failed: {status_line!r}")

    expected_accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
    if expected_accept.encode() not in resp:
        raise ConnectionError("handshake: Sec-WebSocket-Accept mismatch")


def open_ws(host, port, path, timeout=5.0):
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    ws_handshake(sock, host, path)
    return sock


def send_torn(sock, frame_bytes, split_at, delay=0.02, verbose=False):
    """Send frame_bytes as separate writes broken at each offset in
    split_at (an int or list of ints, strictly increasing, each < len).
    TCP_NODELAY + a small inter-write delay makes it very likely each piece
    lands in its own TCP segment / _onData() call on the receiver."""
    if isinstance(split_at, int):
        split_at = [split_at]
    offsets = [0] + sorted(split_at) + [len(frame_bytes)]
    for i in range(len(offsets) - 1):
        piece = frame_bytes[offsets[i]:offsets[i + 1]]
        if not piece:
            continue
        if verbose:
            print(f"    write[{offsets[i]}:{offsets[i+1]}] = {piece.hex()}")
        sock.sendall(piece)
        if i < len(offsets) - 2:
            time.sleep(delay)


def drain(sock, timeout=0.5):
    """Best-effort read of whatever the server sends back, for visibility.
    Not a WS frame decoder -- just enough to see the connection is alive
    and to pace the UAF repro (see uaf_close_ack)."""
    sock.settimeout(timeout)
    try:
        return sock.recv(4096)
    except socket.timeout:
        return b""
    except OSError:
        return b""


class _RecvBuf:
    """Small buffered reader so recv_ws_frame() can pull exactly as many
    bytes as it needs across several recv() calls without losing whatever
    arrives past a frame boundary (server may pipeline more than one
    frame -- e.g. the connect-time ping -- ahead of the one we want)."""

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def need(self, n, timeout):
        self.sock.settimeout(timeout)
        while len(self.buf) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("connection closed while reading frame")
            self.buf += chunk

    def take(self, n, timeout):
        self.need(n, timeout)
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def wait_teardown(self, timeout=5.0):
        """Wait, in total silence (no further writes), for the server to
        end the TCP connection. Returns a (kind, detail) pair:
          ("eof", None)      -- clean FIN: recv() returned b""
          ("reset", exc)     -- RST or similar: recv() raised an OSError
          ("data", bytes)    -- unread bytes exist (already-buffered
                                 leftovers count too -- this method must
                                 be used on the SAME _RecvBuf that did any
                                 earlier reads on this socket, or leftover
                                 bytes it isn't aware of will be missed)
          ("timeout", None)  -- still open after `timeout` seconds
        Whether real TCP/BSD-socket semantics give a FIN or a RST here
        depends on whether the server closed with unconsumed data still
        sitting in its receive buffer -- a RST is the normal/expected
        outcome when there is such leftover data, and a bug if there is
        not (i.e. the peer's last message, such as its own close frame,
        was the last thing we sent). Callers decide which outcomes count
        as a pass."""
        if self.buf:
            return "data", self.buf
        self.sock.settimeout(timeout)
        try:
            more = self.sock.recv(4096)
        except socket.timeout:
            return "timeout", None
        except OSError as e:
            return "reset", e
        return ("eof", None) if more == b"" else ("data", more)


def recv_ws_frame(rb, timeout=2.0):
    """Read exactly one WS frame sent BY the server off an _RecvBuf.
    Server frames are always unmasked (RFC 6455 5.1: servers MUST NOT
    mask). Returns (opcode, fin, payload), or None on timeout."""
    try:
        hdr = rb.take(2, timeout)
        fin = bool(hdr[0] & 0x80)
        opcode = hdr[0] & 0x0F
        masked = bool(hdr[1] & 0x80)
        length = hdr[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", rb.take(2, timeout))[0]
        elif length == 127:
            length = struct.unpack(">Q", rb.take(8, timeout))[0]
        key = rb.take(4, timeout) if masked else None
        payload = rb.take(length, timeout)
        if masked:
            payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
        return opcode, fin, payload
    except socket.timeout:
        return None


def recv_close_code(rb, timeout_total=3.0):
    """Read frames off an _RecvBuf until a CLOSE frame or the connection
    ends; return the close code found in the CLOSE frame's payload, 0 if
    a CLOSE frame arrived with no code, or None if the connection went
    away (or timed out) without ever sending one. Skips over any other
    frames the server may send first (e.g. its connect-time ping).

    Takes an _RecvBuf, not a bare socket: any bytes read past the CLOSE
    frame's boundary (e.g. because the OS handed us a chunk containing
    the start of a *later* message too) stay buffered in it rather than
    being silently discarded, so a subsequent read on the same _RecvBuf
    -- including rb.wait_teardown() -- sees them. Passing a fresh
    _RecvBuf each call, or mixing this with raw sock.recv() calls on the
    same socket, will intermittently lose data and misattribute stale
    buffered frames as unexpected post-close traffic."""
    deadline = time.time() + timeout_total
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None
        try:
            f = recv_ws_frame(rb, timeout=remaining)
        except ConnectionError:
            return None  # connection closed without ever sending a close frame
        if f is None:
            return None  # timed out
        opcode, _fin, payload = f
        if opcode == OPCODE_CLOSE:
            return struct.unpack(">H", payload[:2])[0] if len(payload) >= 2 else 0


def check_alive(host, port, timeout=5.0):
    """Liveness oracle: a fresh HTTP connection to /clients. Deliberately
    independent of WS framing so it still works even if the WS endpoint
    itself is wedged."""
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", "/clients")
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp.status == 200 and body.startswith(b"{")
    except OSError as e:
        return False


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


def case_header_split_small(host, port, path, delay, verbose):
    """7-bit-length masked TEXT frame (2 header + 4 mask = 6 bytes): tear at
    every possible byte boundary in the header, including mid-mask-key."""
    payload = b"hi"
    frame, hlen = build_frame(OPCODE_TEXT, payload, mask=True)
    ok = True
    for split in range(1, hlen):
        sock = open_ws(host, port, path, timeout=5.0)
        try:
            if verbose:
                print(f"  split at byte {split}/{hlen}")
            send_torn(sock, frame, split, delay=delay, verbose=verbose)
            drain(sock)
        finally:
            sock.close()
        time.sleep(delay)
        if not check_alive(host, port):
            print(f"  FAIL: device unresponsive after split at byte {split}")
            ok = False
    return ok


def case_header_split_16bit(host, port, path, delay, verbose):
    """16-bit extended length (2 header + 2 length + 4 mask = 8 bytes):
    tear at every byte boundary."""
    payload = b"x" * 200  # forces the 16-bit length form
    frame, hlen = build_frame(OPCODE_TEXT, payload, mask=True, len_form="16")
    ok = True
    for split in range(1, hlen):
        sock = open_ws(host, port, path, timeout=5.0)
        try:
            if verbose:
                print(f"  split at byte {split}/{hlen}")
            send_torn(sock, frame, split, delay=delay, verbose=verbose)
            drain(sock)
        finally:
            sock.close()
        time.sleep(delay)
        if not check_alive(host, port):
            print(f"  FAIL: device unresponsive after split at byte {split}")
            ok = False
    return ok


def case_header_split_64bit(host, port, path, delay, verbose):
    """64-bit extended length (2 header + 8 length + 4 mask = 14 bytes):
    tear at every byte boundary. This is the fully-unrolled Length8_1..8
    state chain -- the most state transitions of any header form."""
    payload = b"x" * 40
    frame, hlen = build_frame(OPCODE_BIN, payload, mask=True, len_form="64")
    ok = True
    for split in range(1, hlen):
        sock = open_ws(host, port, path, timeout=5.0)
        try:
            if verbose:
                print(f"  split at byte {split}/{hlen}")
            send_torn(sock, frame, split, delay=delay, verbose=verbose)
            drain(sock)
        finally:
            sock.close()
        time.sleep(delay)
        if not check_alive(host, port):
            print(f"  FAIL: device unresponsive after split at byte {split}")
            ok = False
    return ok


def case_safari_close_no_mask(host, port, path, delay, verbose):
    """The literal Safari bug: FIN+CLOSE, masked bit set, len=0, and then
    NO mask bytes ever sent -- the whole frame is 2 bytes, full stop. This
    must be treated as a 0-length unmasked close, not left hanging forever
    waiting for 4 mask bytes that will never come."""
    frame = bytes([0x88, 0x80])  # FIN|CLOSE, MASK=1 LEN=0, no mask key follows
    sock = open_ws(host, port, path, timeout=5.0)
    try:
        if verbose:
            print(f"  single write: {frame.hex()}")
        sock.sendall(frame)
        reply = drain(sock, timeout=1.0)
        if verbose:
            print(f"  reply: {reply.hex()}")
    finally:
        sock.close()
    time.sleep(delay)
    return check_alive(host, port)


def case_close_reason_len1(host, port, path, delay, verbose):
    """Close frame that declares a 1-byte payload -- shorter than the
    2-byte close-code field. Regression for commit 9ba38e6 ("Discard torn
    close reasons"): must not read a second byte that was never sent."""
    frame, _ = build_frame(OPCODE_CLOSE, b"\x00", mask=True, declared_len=1)
    sock = open_ws(host, port, path, timeout=5.0)
    try:
        if verbose:
            print(f"  single write: {frame.hex()}")
        sock.sendall(frame)
        drain(sock, timeout=1.0)
    finally:
        sock.close()
    time.sleep(delay)
    return check_alive(host, port)


def case_close_reason_torn(host, port, path, delay, verbose):
    """Close frame with a real code + reason string, but the 2-byte code
    itself is split across two writes. The parser is expected to discard
    the reason (not attempt to reassemble it across the tear) rather than
    read stale/garbage bytes."""
    frame, hlen = build_frame(OPCODE_CLOSE, build_close_payload(4000, b"custom reason"), mask=True)
    sock = open_ws(host, port, path, timeout=5.0)
    try:
        split = hlen + 1  # tear inside the 2-byte close code
        if verbose:
            print(f"  split at byte {split}/{len(frame)}")
        send_torn(sock, frame, split, delay=delay, verbose=verbose)
        drain(sock, timeout=1.0)
    finally:
        sock.close()
    time.sleep(delay)
    return check_alive(host, port)


def case_huge_length_truncation(host, port, path, delay, verbose):
    """Declare a 64-bit length far beyond what size_t can hold on a 32-bit
    target (e.g. ESP32/ESP8266), but only ever send a handful of payload
    bytes, then abandon the frame. Regression for commit 24da481: the old
    `(size_t)(_pinfo.len - _pinfo.index)` cast (before the std::min) could
    truncate a huge 64-bit delta down to a small/wrong size_t *before* the
    min() against plen was applied, on platforms where size_t is 32 bits.
    We don't need to actually transmit 4+ GB -- just declare it and confirm
    the parser waits sanely instead of misbehaving on the first chunk."""
    declared = (1 << 32) + 16  # > UINT32_MAX
    hdr, hlen = build_frame(OPCODE_BIN, b"", mask=True, len_form="64", declared_len=declared)
    payload_chunk = bytes(range(16))
    key = hdr[hlen - 4:hlen]
    masked_chunk = bytes(b ^ key[i % 4] for i, b in enumerate(payload_chunk))
    frame = hdr + masked_chunk

    sock = open_ws(host, port, path, timeout=5.0)
    try:
        if verbose:
            print(f"  declared_len={declared}, sending header + {len(payload_chunk)} bytes then abandoning")
        sock.sendall(frame)
        drain(sock, timeout=0.5)
    finally:
        sock.close()
    time.sleep(delay)
    return check_alive(host, port)


def case_torn_ping_reassembly(host, port, path, delay, verbose):
    """A PING with a payload torn mid-payload (not just mid-header) across
    two writes. Regression test for the control-frame reassembly fix: the
    PONG reply must echo the FULL original payload, not just whichever
    fragment happened to complete the frame on the wire."""
    payload = bytes(range(40))  # distinctive, order-sensitive content
    frame, hlen = build_frame(OPCODE_PING, payload, mask=True)
    split = hlen + 17  # tear inside the payload itself
    sock = open_ws(host, port, path, timeout=5.0)
    try:
        if verbose:
            print(f"  split at byte {split}/{len(frame)} (payload torn at offset {split - hlen})")
        send_torn(sock, frame, split, delay=delay, verbose=verbose)

        rb = _RecvBuf(sock)
        got = None
        for _ in range(5):  # skip past the server's own connect-time ping, if still pending
            f = recv_ws_frame(rb, timeout=2.0)
            if f is None:
                break
            opcode, _fin, data = f
            if opcode == OPCODE_PONG:
                got = data
                break
        if got != payload:
            print(f"  FAIL: pong payload mismatch: expected {payload.hex()}")
            print(f"                            got {(got or b'').hex()}")
            return False
        if verbose:
            print(f"  pong payload matched ({len(got)} bytes)")
    except (ConnectionError, OSError) as e:
        print(f"  FAIL: {e}")
        return False
    finally:
        sock.close()
    time.sleep(delay)
    return check_alive(host, port)


def case_control_frame_between_continuations(host, port, path, delay, verbose):
    """A fragmented TEXT message with a PING interleaved between its frames
    (RFC 6455 5.4: control frames MAY be injected mid-message). Uses the
    sketch's "trace" command to check the DATA events: frame numbers must
    run 0, 1, 2 across the PING, and the PING must be answered."""
    parts = [b"frag0", b"frag1", b"frag2"]
    ping_payload = b"probe"
    wire = b"".join([
        build_frame(OPCODE_TEXT, parts[0], fin=False)[0],
        build_frame(OPCODE_PING, ping_payload)[0],
        build_frame(OPCODE_CONT, parts[1], fin=False)[0],
        build_frame(OPCODE_CONT, parts[2], fin=True)[0],
    ])
    expected = [
        f"trace data num=0 op=1 msgop=1 final=0 index=0 len=5 data={parts[0].hex()}",
        "trace ping",
        f"trace data num=1 op=0 msgop=1 final=0 index=0 len=5 data={parts[1].hex()}",
        f"trace data num=2 op=0 msgop=1 final=1 index=0 len=5 data={parts[2].hex()}",
    ]

    sock = open_ws(host, port, path, timeout=5.0)
    try:
        rb = _RecvBuf(sock)
        sock.sendall(build_frame(OPCODE_TEXT, b"trace")[0])
        traces, pong = [], None
        deadline = time.time() + 3.0
        sent = False
        # Control frames are queued ahead of data messages, so the PONG's
        # position relative to the trace reports is not significant.
        while len(traces) < len(expected) or pong is None:
            remaining = deadline - time.time()
            f = recv_ws_frame(rb, timeout=remaining) if remaining > 0 else None
            if f is None:
                break
            opcode, _fin, data = f
            if opcode == OPCODE_PONG:
                pong = data
            elif opcode == OPCODE_TEXT and data == b"trace on" and not sent:
                sock.sendall(wire)
                sent = True
            elif opcode == OPCODE_TEXT and data.startswith(b"trace "):
                traces.append(data.decode(errors="replace"))
        if verbose:
            for t in traces:
                print(f"  {t}")
        if not sent:
            print("  FAIL: no 'trace on' reply -- is WebSocketTest.ino up to date?")
            return False
        if traces != expected:
            print("  FAIL: trace mismatch")
            for i in range(max(len(traces), len(expected))):
                exp = expected[i] if i < len(expected) else "(none)"
                got = traces[i] if i < len(traces) else "(none)"
                print(f"    expected: {exp}\n         got: {got}")
            return False
        if pong != ping_payload:
            print(f"  FAIL: pong payload: expected {ping_payload!r}, got {pong!r}")
            return False
    except (ConnectionError, OSError) as e:
        print(f"  FAIL: {e}")
        return False
    finally:
        sock.close()
    time.sleep(delay)
    return check_alive(host, port)


def case_oversized_control_frame_dos(host, port, path, delay, verbose):
    """ADVERSARIAL. RFC 6455 5.5 caps control-frame payloads at 125 bytes.
    Sends a PING declaring (and actually carrying) a 40000-byte payload via
    the 16-bit length form. Checks two things: the device survives, AND it
    actually reports the violation -- the server should send back a CLOSE
    frame with code 1002 (WS_CLOSE_PROTOCOL_ERROR) before the connection
    goes away, not just silently vanish. On a build without the
    control-frame length-cap check this used to be an uncontrolled ~40KB
    heap allocation and could crash the device outright."""
    payload = bytes((i % 256) for i in range(40000))
    frame, hlen = build_frame(OPCODE_PING, payload, mask=True, len_form="16")
    sock = open_ws(host, port, path, timeout=5.0)
    rb = _RecvBuf(sock)
    ok = True
    try:
        if verbose:
            print(f"  sending {len(frame)}-byte single write (declared control-frame len=40000)")
        sock.sendall(frame)
        code = recv_close_code(rb, timeout_total=3.0)
        if verbose:
            print(f"  close code: {code}")
        if code != WS_CLOSE_PROTOCOL_ERROR:
            print(f"  FAIL: expected close code {WS_CLOSE_PROTOCOL_ERROR}, got {code}")
            ok = False
    except OSError as e:
        print(f"  FAIL: {e}")
        ok = False
    finally:
        sock.close()
    time.sleep(delay)
    return ok and check_alive(host, port)


def case_control_frame_length_truncation(host, port, path, delay, verbose):
    """ADVERSARIAL -- targets a specific suspected bug, not just a spec
    violation. A control-frame opcode (PING) using the 64-bit length form
    with a declared length of (1<<32)+16, which truncates to 16 when cast
    to a 32-bit size_t. If the torn-control-frame reassembly buffer were
    allocated with that truncated size while the accompanying memcpy used
    the correctly-computed (un-truncated) byte count, this would be a heap
    buffer overflow of attacker-controlled data on any 32-bit target
    (ESP32/ESP8266) -- and it was, before the length-cap check. Sends the
    header plus 512 payload bytes in a single write (still "torn" relative
    to the frame's enormous declared length, so it takes the buffering
    path if the cap check is missing), and now also checks that a CLOSE
    frame with code 1002 comes back rather than the connection just
    vanishing (or the device crashing)."""
    declared = (1 << 32) + 16  # truncates to 16 as a 32-bit size_t
    hdr, hlen = build_frame(OPCODE_PING, b"", mask=True, len_form="64", declared_len=declared)
    overflow_chunk = bytes((i % 256) for i in range(512))  # >> the truncated 16-byte allocation
    key = hdr[hlen - 4:hlen]
    masked_chunk = bytes(b ^ key[i % 4] for i, b in enumerate(overflow_chunk))
    frame = hdr + masked_chunk

    sock = open_ws(host, port, path, timeout=5.0)
    rb = _RecvBuf(sock)
    ok = True
    try:
        if verbose:
            print(f"  declared_len={declared} (truncates to 16 as size_t); sending header + {len(overflow_chunk)} bytes in one write")
        sock.sendall(frame)
        code = recv_close_code(rb, timeout_total=3.0)
        if verbose:
            print(f"  close code: {code}")
        if code != WS_CLOSE_PROTOCOL_ERROR:
            print(f"  FAIL: expected close code {WS_CLOSE_PROTOCOL_ERROR}, got {code}")
            ok = False
    except OSError as e:
        print(f"  FAIL: {e}")
        ok = False
    finally:
        sock.close()
    time.sleep(delay)
    return ok and check_alive(host, port)


def case_reserved_control_opcode(host, port, path, delay, verbose):
    """A control frame with a reserved/undefined opcode (0xB), well within
    the 125-byte length cap so it's not caught by that check -- this
    exercises the separate "unknown control frame" branch in
    _handleClientFrame specifically (opcode 0x8/0x9/0xA all have defined
    meanings; 0xB-0xF do not, and RFC 6455 5.5 requires failing the
    connection on receipt). Checks that the server reports it as a
    protocol error (close code 1002) rather than silently ignoring it or
    misinterpreting it as one of the known control opcodes."""
    frame, _ = build_frame(OPCODE_RESERVED_CONTROL, b"unknown-opcode", mask=True)
    sock = open_ws(host, port, path, timeout=5.0)
    rb = _RecvBuf(sock)
    ok = True
    try:
        if verbose:
            print(f"  sending single write with reserved control opcode 0x{OPCODE_RESERVED_CONTROL:X}")
        sock.sendall(frame)
        code = recv_close_code(rb, timeout_total=3.0)
        if verbose:
            print(f"  close code: {code}")
        if code != WS_CLOSE_PROTOCOL_ERROR:
            print(f"  FAIL: expected close code {WS_CLOSE_PROTOCOL_ERROR}, got {code}")
            ok = False
    except OSError as e:
        print(f"  FAIL: {e}")
        ok = False
    finally:
        sock.close()
    time.sleep(delay)
    return ok and check_alive(host, port)


def case_server_closes_without_client_ack(host, port, path, delay, verbose):
    """Trigger a protocol-violation close (reserved control opcode), then
    deliberately do NOT send anything back and do NOT close our own
    socket -- simulating a client that never cooperates. Confirms the
    server tears down the TCP connection on its own initiative (it must
    not wait for a close-frame ack that will never come), and that the
    client slot is freed server-side, within a bounded time. This is the
    regression test for the AwsParseState::Error design: close() queues
    the close frame and _runQueue's existing "WS_DISCONNECT completes ->
    _client->close()" logic (AsyncWebSocket.cpp ~340-354) is relied on to
    actually finish the job -- this checks that reliance is justified.

    Note: whether the server's TCP teardown surfaces to us as a clean EOF
    (recv() -> b"") or a RST (ConnectionResetError) depends on whether we
    left unread data sitting in its receive buffer when it closed (a
    small single-write violation frame tends to give a clean FIN; a large
    one like oversized_control_frame_dos tends to give a RST, because
    lwIP/BSD-socket semantics reset a connection closed with unconsumed
    inbound data rather than FIN it) -- both are equally valid proof the
    server actively closed the connection, so either is accepted here."""
    frame, _ = build_frame(OPCODE_RESERVED_CONTROL, b"never-acked", mask=True)
    sock = open_ws(host, port, path, timeout=5.0)
    rb = _RecvBuf(sock)
    ok = True
    try:
        sock.sendall(frame)
        code = recv_close_code(rb, timeout_total=3.0)
        if verbose:
            print(f"  close code: {code}")
        if code != WS_CLOSE_PROTOCOL_ERROR:
            print(f"  FAIL: expected close code {WS_CLOSE_PROTOCOL_ERROR}, got {code}")
            ok = False

        # Deliberately silent from here: no ack frame, no sock.close().
        kind, detail = rb.wait_teardown(timeout=5.0)
        if verbose:
            print(f"  teardown: {kind} {detail!r}")
        if kind == "timeout":
            print("  FAIL: server left the TCP connection open 5s after its own close frame, with us completely silent")
            ok = False
        elif kind == "data":
            print(f"  FAIL: expected EOF or RST, got unexpected data instead: {detail!r}")
            ok = False
        # "eof" and "reset" are both acceptable here -- see docstring.
    except OSError as e:
        print(f"  FAIL: {e}")
        ok = False
    finally:
        sock.close()  # only now, to release our own fd; the server side was already done
    time.sleep(delay)
    return ok and check_alive(host, port)


def case_client_initiated_close_eof(host, port, path, delay, verbose):
    """A well-behaved client sends a single, well-formed CLOSE frame
    (code 1000) as the ONLY thing it ever sends on the connection -- no
    protocol violation, no leftover unread data sitting in the server's
    receive buffer by the time it closes. This is the literal case
    "the disconnect is the last message from the client": once the
    server has echoed its own CLOSE frame back, the underlying TCP
    connection must end with a clean FIN (recv() -> b""), never a RST --
    unlike server_closes_without_client_ack, a RST here is a FAIL, not an
    accepted alternative, because there is nothing left unconsumed that
    would justify one. Regression test for AsyncTCP's close-in-callback-
    safety fixes (a RST was observed here before those landed)."""
    frame, _ = build_frame(OPCODE_CLOSE, build_close_payload(WS_CLOSE_NORMAL), mask=True)
    sock = open_ws(host, port, path, timeout=5.0)
    rb = _RecvBuf(sock)
    ok = True
    try:
        sock.sendall(frame)  # first and ONLY thing this client ever sends
        code = recv_close_code(rb, timeout_total=3.0)
        if verbose:
            print(f"  server echoed close code: {code}")
        if code != WS_CLOSE_NORMAL:
            print(f"  FAIL: expected server to echo close code {WS_CLOSE_NORMAL}, got {code}")
            ok = False

        # Still silent, socket still open on our end.
        kind, detail = rb.wait_teardown(timeout=5.0)
        if verbose:
            print(f"  teardown: {kind} {detail!r}")
        if kind != "eof":
            print(f"  FAIL: expected a clean EOF (FIN) -- nothing was left unconsumed -- but got {kind} ({detail!r})")
            ok = False
    except OSError as e:
        print(f"  FAIL: {e}")
        ok = False
    finally:
        sock.close()
    time.sleep(delay)
    return ok and check_alive(host, port)


def case_uaf_close_ack(host, port, path, delay, verbose):
    """Regression test for the use-after-free fixed in AsyncWebSocket.cpp's
    trailing zero-length-frame dispatch: server-initiated close, acked by a
    lone close frame sent as its own isolated write (so its parse ends in
    AwsParseState::Payload/len==0 exactly at the tail of that _onData call
    -- the same shape as the original bug). The ack is also this client's
    last message, so -- like case_client_initiated_close_eof -- the
    connection must end with a clean FIN, not a RST."""
    sock = open_ws(host, port, path, timeout=5.0)
    rb = _RecvBuf(sock)
    ok = True
    try:
        # Ask the server to close *this* connection (AsyncWebSocketClient::close()),
        # which sets _status = WS_DISCONNECTING and queues the server's own close frame.
        # Read it structurally (not a single raw recv()) so it's fully consumed off
        # the SAME _RecvBuf we'll use below -- a raw recv() here could leave the
        # server's connect-time broadcast/ping sitting unread and misread later as
        # unexpected post-close traffic.
        cmd_frame, _ = build_frame(OPCODE_TEXT, b"close", mask=True)
        sock.sendall(cmd_frame)
        server_code = recv_close_code(rb, timeout_total=2.0)
        if verbose:
            print(f"  server's own close code: {server_code}")
        if server_code != WS_CLOSE_NORMAL:
            print(f"  FAIL: expected the server's self-initiated close to use code {WS_CLOSE_NORMAL}, got {server_code}")
            ok = False

        # Now ack with our own minimal close frame, as a single isolated
        # send() -- this is what completes the handshake and used to
        # trigger the UAF. It's also the last thing we ever send.
        ack, _ = build_frame(OPCODE_CLOSE, b"", mask=True)
        if verbose:
            print(f"  ack write: {ack.hex()}")
        sock.sendall(ack)

        kind, detail = rb.wait_teardown(timeout=5.0)
        if verbose:
            print(f"  teardown: {kind} {detail!r}")
        if kind != "eof":
            print(f"  FAIL: expected a clean EOF (FIN) after our ack completed the handshake, got {kind} ({detail!r})")
            ok = False
    except OSError as e:
        print(f"  FAIL: {e}")
        ok = False
    finally:
        sock.close()
    time.sleep(delay)
    return ok and check_alive(host, port)


CASES = {
    "header_split_small": case_header_split_small,
    "header_split_16bit": case_header_split_16bit,
    "header_split_64bit": case_header_split_64bit,
    "safari_close_no_mask": case_safari_close_no_mask,
    "close_reason_len1": case_close_reason_len1,
    "close_reason_torn": case_close_reason_torn,
    "huge_length_truncation": case_huge_length_truncation,
    "torn_ping_reassembly": case_torn_ping_reassembly,
    "control_frame_between_continuations": case_control_frame_between_continuations,
    "uaf_close_ack": case_uaf_close_ack,
    "client_initiated_close_eof": case_client_initiated_close_eof,
    "reserved_control_opcode": case_reserved_control_opcode,
    "server_closes_without_client_ack": case_server_closes_without_client_ack,
    # --- adversarial: may crash/reboot the device on a build that hasn't
    # --- added a control-frame length-cap check. Kept last so the rest of
    # --- the suite above still gets a result even if these take the board down.
    "oversized_control_frame_dos": case_oversized_control_frame_dos,
    "control_frame_length_truncation": case_control_frame_length_truncation,
}


CRASH_MARKERS = (
    "Guru Meditation Error",
    "Rebooting...",
    "CORRUPT HEAP",
    "assert failed",
    "Backtrace:",
    "***ERROR***",
    "abort() was called",
)


class SerialWatcher:
    """Best-effort crash detector: tails a serial console (stdlib only,
    via termios -- no pyserial dependency) and flags known ESP crash/
    reboot banners seen during a test case.

    This exists because the HTTP liveness probe (check_alive) is NOT a
    reliable oracle on its own: an ESP32 that panics and auto-reboots can
    finish rebooting and start answering HTTP again well inside a 5s
    liveness-check window, so a real crash silently reads as a PASS. This
    is not hypothetical -- both adversarial cases below crashed the
    device (a lwIP rcv-window assert and a heap-poisoning "CORRUPT HEAP"
    abort, respectively) and check_alive() missed both, because the
    device came back up before the next probe."""

    def __init__(self, port, baud=115200):
        import termios
        import tty

        self.fd = os.open(port, os.O_RDONLY | os.O_NOCTTY)
        attrs = termios.tcgetattr(self.fd)
        tty.setraw(self.fd)
        baud_const = getattr(termios, f"B{baud}")
        attrs[4] = attrs[5] = baud_const  # ispeed, ospeed
        termios.tcsetattr(self.fd, termios.TCSANOW, attrs)

        self.lines = collections.deque(maxlen=4000)
        self.lock = threading.Lock()
        self._stop = False
        self.thread = threading.Thread(target=self._reader, daemon=True)
        self.thread.start()

    def _reader(self):
        buf = b""
        while not self._stop:
            try:
                chunk = os.read(self.fd, 4096)
            except OSError:
                break
            if not chunk:
                continue
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                with self.lock:
                    self.lines.append(line.decode(errors="replace"))

    def close(self):
        self._stop = True
        try:
            os.close(self.fd)
        except OSError:
            pass

    def mark(self):
        """Snapshot the current read position, to check_since() later."""
        with self.lock:
            return len(self.lines)

    def check_since(self, mark, settle=1.5):
        """Return the first crash-marker line seen at/after `mark`, after
        waiting `settle` seconds for any in-flight reboot banner to finish
        printing (a panic + reboot trace takes a moment to fully emit)."""
        time.sleep(settle)
        with self.lock:
            lines = list(self.lines)[mark:]
        for line in lines:
            if any(marker in line for marker in CRASH_MARKERS):
                return line
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", help="ESP IP or hostname (e.g. 192.168.4.1)")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--path", default="/ws")
    ap.add_argument("--case", action="append", dest="cases", help="run only this case (repeatable); default: all")
    ap.add_argument("--delay", type=float, default=0.02, help="seconds between torn writes / after each case (default 0.02)")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--list", action="store_true", help="list available cases and exit")
    ap.add_argument(
        "--serial", metavar="PORT", help="serial console to watch for crash/reboot banners while testing (e.g. /dev/ttyUSB0). "
        "Strongly recommended: the HTTP liveness check alone can miss a crash if the device reboots and recovers between probes."
    )
    ap.add_argument("--baud", type=int, default=115200)
    args = ap.parse_args()

    if args.list:
        for name, fn in CASES.items():
            print(f"{name}: {(fn.__doc__ or '').strip().splitlines()[0] if fn.__doc__ else ''}")
        return 0

    if not args.host:
        ap.error("--host is required (unless --list)")

    if not check_alive(args.host, args.port):
        print(f"ERROR: {args.host}:{args.port}/clients not reachable before testing has even started -- aborting")
        return 2

    watcher = None
    if args.serial:
        try:
            watcher = SerialWatcher(args.serial, args.baud)
        except OSError as e:
            print(f"WARNING: could not open {args.serial} ({e}); continuing without the serial crash-watch")
    else:
        print("NOTE: no --serial given. The HTTP liveness check alone can miss a crash that the device")
        print("      recovers from before the next probe -- pass --serial /dev/ttyUSB0 for a reliable oracle.")

    names = args.cases or list(CASES.keys())
    results = {}
    crash_lines = {}
    for name in names:
        fn = CASES.get(name)
        if fn is None:
            print(f"unknown case: {name} (--list to see available cases)")
            return 2
        print(f"=== {name} ===")
        mark = watcher.mark() if watcher else None
        try:
            ok = fn(args.host, args.port, args.path, args.delay, args.verbose)
        except (ConnectionError, OSError) as e:
            print(f"  EXCEPTION: {e}")
            ok = False
        if watcher:
            crash_line = watcher.check_since(mark)
            if crash_line:
                if ok:
                    print(f"  (HTTP liveness check passed, but the device crashed and recovered during this case)")
                ok = False
                crash_lines[name] = crash_line
        results[name] = ok
        print(f"  {'PASS' if ok else 'FAIL'}")
        if name in crash_lines:
            print(f"  serial: {crash_lines[name]}")

    if watcher:
        watcher.close()

    print("\n--- summary ---")
    failed = [n for n, ok in results.items() if not ok]
    for n, ok in results.items():
        marker = f"  [{crash_lines[n]}]" if n in crash_lines else ""
        print(f"  {'PASS' if ok else 'FAIL'}  {n}{marker}")
    if failed:
        print(f"\n{len(failed)}/{len(results)} case(s) failed.")
        if not args.serial:
            print("No --serial was given -- a crash-and-recover could be hiding in a case reported PASS above.")
        return 1
    print(f"\nAll {len(results)} case(s): device stayed responsive after every torn/malformed frame" + (" (serial-verified)." if watcher else "."))
    if not watcher:
        print("Note: this is an HTTP-only liveness oracle, not a correctness proof -- re-run with --serial")
        print("for a much stronger check, and/or pair with an ASan/UBSan host build of the parser.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
