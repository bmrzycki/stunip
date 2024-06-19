#!/usr/bin/env python3
"Obtain an IPv4 NAT address from a STUN server"

import socket

from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from random import choice
from signal import signal, SIGPIPE, SIG_DFL
from struct import pack, unpack
from sys import stdout
from sys import exit as sys_exit
from uuid import uuid4

__author__ = "Brian Rzycki"
__copyright__ = "Copyright 2024, Brian Rzycki"
__credits__ = ["Brian Rzycki"]
__license__ = "Apache-2.0"
__version__ = "2.0.0"
__maintainer__ = "Brian Rzycki"
__email__ = "brzycki@gmail.com"
__status__ = "Production"

STUN_PORT = 3478
STUN_SERVERS = [
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
    "stun3.l.google.com:19302",
    "stun4.l.google.com:19302",
]

# From the Section 6 RFC 5389:
#     The magic cookie field MUST contain the fixed value 0x2112A442 in
#     network byte order. In RFC 3489, this field was part of the
#     transaction ID; placing the magic cookie in this location allows
#     a server to detect if the client will understand certain attributes
#     that were added in this revised specification.
MAGIC_COOKIE = [0x21, 0x12, 0xA4, 0x42]


def _xor_addr(addr):
    """
    The XOR-MAPPED-ADDRESS attribute trivially obscures the IPv4 address
    by XORing each byte with the MAGIC_COOKIE.
    """
    tmp = b""
    for idx in range(4):
        tmp += pack("!B", addr[idx] ^ MAGIC_COOKIE[idx])
    return tmp


def _xor_addr_noop(addr):
    """
    A no-op variant which does nothing to the input address.
    """
    return addr


class WireFormat:
    """
    We use the older https://tools.ietf.org/html/rfc3489 layout.
    Newer RFCs for STUN:
        https://tools.ietf.org/html/rfc5389
        https://tools.ietf.org/html/rfc5769
    RFC 5389 requires servers to be backward compatible with RFC 3489
    which is simpler and maximizes compatibility. We use very little
    of the protocol to determine our external IPv4 address.
    """

    def __init__(self):
        self.addr = ""
        self.tid = b""
        self.reset()

    def dump(self, buf):
        "Dump the conents of a buf to stdout, useful for packet debug."
        for hexbyte in buf:
            stdout.write(f"0x{ord(hexbyte):02x} ")
        stdout.write("\n")

    def reset(self):
        "Resets the internal object state."
        self.addr = ""

        # The Transaction ID is 16 bytes used to pair request/response
        # packets. While RFC 3489 assigned no meaning to these bytes the
        # updated RFC 5389 uses part of it to detect the new protocol.
        # Setting bytes[0:3] == MAGIC_COOKIE informs the server we
        # support RFC 5389. Force RFC 3489 by assigning id[0] to 0 and
        # id[1:16] to random bytes.
        self.tid = pack("!B15s", 0, uuid4().bytes)

    def request(self):
        "Sends a specialized STUN request mesage."
        # A STUN header contains a Message Type, Message Length, and
        # a Transaction ID. The shortest and simplest request type is
        # a Binding Request (0x0001) with a Message Length of 0 for a
        # total of 20 bytes sent. See response() below for the header
        # layout.
        return pack("!HH16s", 0x0001, 0, self.tid)

    def response(self, buf, cached=True):
        "Processes a simplified STUN response."
        # pylint: disable=too-many-return-statements
        if cached and self.addr:
            return True
        self.addr = ""

        # The buffer must contain the following bytes: STUN Header (20),
        # MAPPED-ADDRESS Header (4), and a MAPPED-ADDRESS Value (8). Don't
        # check for exactly 20+4+8 (32) bytes because some servers still
        # use RFC 5389 even after we requested the older layout.
        if len(buf) < 32:
            return False

        # ==================== STUN Header (20 bytes) =====================
        #  0                   1                   2                   3
        #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |      STUN Message Type        |         Message Length        |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #                          Transaction ID
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #                                                                 |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # A Binding Response (0x0101) with the same Transaction ID is the
        # only valid response to our Binding Request.
        stun_type, stun_len, stun_id = unpack("!HH16s", buf[:20])
        if stun_type != 0x0101 or stun_id != self.tid:
            return False

        # Sanity check: Attribute payload is Message Length bytes.
        attrs = buf[20:]
        if stun_len != len(attrs):
            return False

        # =========== MAPPED-ADDRESS Header Attribute (4 bytes) ===========
        #  0                   1                   2                   3
        #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |             Type              |            Length             |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                     Value (MAPPED-ADDRESS)
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #                                                                 |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # RFC 3489 denotes only one, and mandatory, attribute response:
        #   Type = 0x0001 (MAPPED-ADDRESS), Length = 8
        # Some servers ignore our RFC 3489 request and reply using the
        # the RFC 5389 address variant:
        #   Type = 0x0020 (XOR-MAPPED-ADDRESS), Length = 8
        # The IPv4 XOR variant obscures the Address and Port fields by
        # XORing them with the MAGIC_COOKIE.
        attr_type, value_len = unpack("!HH", attrs[:4])
        if value_len != 8:
            return False
        if attr_type == 0x0001:
            xor_addr = _xor_addr_noop
        elif attr_type == 0x0020:
            xor_addr = _xor_addr
        else:
            return False
        value = attrs[4:]

        # ================ MAPPED-ADDRESS Value (8 bytes) =================
        #  0                   1                   2                   3
        #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |  (Alignment)  |    Family     |           Port                |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                             Address                           |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # Alignment and Port are ignored for our use-case and Family is 1
        # which denotes Address is an IPv4 address.
        _, family, _, address = unpack("!BBH4s", value[:8])
        if family != 1:
            return False
        self.addr = socket.inet_ntoa(xor_addr(address))
        return True


class StunIP:
    "Fetch a NAT IPv4 address via the STUN protocol."

    # pylint: disable=too-few-public-methods
    def __init__(self, saddr="0.0.0.0", timeout=0.5, max_tries=10):
        self.max_tries = max_tries
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(timeout)
        self.sock.bind((saddr, 0))  # Request a dynamic source port.

    def nat_ip(self, addr, port=STUN_PORT):
        """
        Returns an IPv4 NAT address as a dotted-quad string using STUN server
        addr listening on port.
        """
        wire = WireFormat()
        for _ in range(self.max_tries):
            self.sock.sendto(wire.request(), (addr, port))
            try:
                if wire.response(self.sock.recv(2048)):
                    return wire.addr
            except socket.timeout:
                pass
        return ""


def main():
    """
    The main routine.
    """
    parser = ArgumentParser(
        description="Fetch external IPv4 address using STUN",
        epilog=f"The default STUN port is {STUN_PORT}.",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-a", "--address", default="0.0.0.0", help="source address")
    parser.add_argument(
        "-m",
        "--max-tries",
        default=10,
        type=int,
        help="max tries to send a STUN request",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        default=0.5,
        type=float,
        help="socket timeout (in seconds) per request attempt",
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "server",
        default=choice(STUN_SERVERS),
        nargs="?",
        help="STUN server[:port]",
    )
    args = parser.parse_args()

    if not args.address:
        parser.error("invalid empty source address")

    if ":" not in args.server:
        args.server += f":{STUN_PORT}"
    daddr, dport = args.server.strip().split(":")[:2]
    if not daddr:
        parser.error("invalid empty server address")
    try:
        dport = int(dport)
    except ValueError:
        parser.error(f"invalid server port '{dport}'")
    if not 0 < dport <= 65535:
        parser.error(f"server port must be 0 < {dport} <= 65535")

    stun = StunIP(args.address, args.timeout, args.max_tries)
    nat_ip = stun.nat_ip(daddr, dport)
    if not nat_ip:
        parser.error("unable to obtain NAT address")
    stdout.write(f"{nat_ip}\n")


if __name__ == "__main__":
    signal(SIGPIPE, SIG_DFL)  # Suppress broken pipe exceptions.
    try:
        main()
    except KeyboardInterrupt:
        sys_exit(1)
