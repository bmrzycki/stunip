#!/usr/bin/env python

import socket
import struct
import sys
import uuid

__author__     = "Brian Rzycki"
__copyright__  = "Copyright 2021, Brian Rzycki"
__credits__    = [ "Brian Rzycki" ]
__license__    = "Apache-2.0"
__version__    = "1.2.0"
__maintainer__ = "Brian Rzycki"
__email__      = "brzycki@gmail.com"
__status__     = "Production"

STUN_PORT = 3478
STUN_SERVERS = [
    "stun.l.google.com:19305",
    "stun1.l.google.com:19305",
    "stun2.l.google.com:19305",
    "stun3.l.google.com:19305",
    "stun4.l.google.com:19305",
]

class WireFormat(object):
    """
    We use the older https://tools.ietf.org/html/rfc3489 layout.
    Newer RFCs for STUN:
        https://tools.ietf.org/html/rfc5389
        https://tools.ietf.org/html/rfc5769
        https://tools.ietf.org/html/rfc5389
    RFC 5389 requires servers to be backward compatible with RFC 3489
    which is simpler and maximizes compatibility. We use very little
    of the protocol to determine our external IPv4 address.
    """
    def __init__(self):
        self.reset()

    def reset(self):
        self.ip = ""

        # The Transaction ID is 16 bytes used to pair request/response
        # packets. While RFC 3489 assigned no meaning to these bytes the
        # updated RFC 5389 uses part of it to detect the new protocol.
        # Setting bytes[0:3] == 0x2112A442 (a "magic cookie") informs
        # the server we support RFC 5389. Force RFC 3489 by assigning
        # id[0] to 0 and id[1:16] to random bytes.
        self.id = struct.pack("!B15s", 0, uuid.uuid4().bytes)

    def request(self):
        # A STUN header contains a Message Type, Message Length, and
        # a Transaction ID. The shortest and simplest request type is
        # a Binding Request (0x0001) with a Message Length of 0 for a
        # total of 20 bytes sent. See response() below for the header
        # layout.
        return struct.pack("!HH16s", 0x0001, 0, self.id)

    def response(self, buf, cached=True):
        if cached and self.ip:
            return True
        self.ip = ""

        # The buffer must contain the following bytes: STUN Header (20),
        # MAPPED-ADDRESS Header (4), and a MAPPED-ADDRESS Value (8). Don't
        # check for exactly 20+4+8 (32) bytes because some servers still
        # use RFC 5389 even after we requested the older format.
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
        stun_type, stun_len, stun_id = struct.unpack("!HH16s", buf[:20])
        if stun_type != 0x0101 or stun_id != self.id:
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
        # A Binding Response has only one valid (and mandatory) Attribute:
        # MAPPED-ADDRESS (0x0001) with a fixed Value length of 8 bytes.
        attr_type, value_len = struct.unpack("!HH", attrs[:4])
        if attr_type != 0x0001 or value_len != 8:
            return False

        # We explicitly limit the size of value because the newer RFC 5389
        # may add additional data of no use to us obtaining our Address.
        value = attrs[4:4+value_len]

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
        _, family, _, address = struct.unpack("!BBH4s", value)
        if family != 1:
            return False

        try:
            ip = socket.inet_ntoa(address)  # Convert to IPv4 dotted-decimal.
        except:
            return False

        self.ip = ip
        return True


class StunIP(object):
    def __init__(self, saddr="0.0.0.0", timeout=0.5, max_tries=10):
        self.max_tries = max_tries
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(timeout)
        self.sock.bind((saddr, 0))  # Request a dynamic source port.

    def ip(self, addr, port=STUN_PORT):
        w = WireFormat()
        for _ in range(self.max_tries):
            self.sock.sendto(w.request(), (addr, port))
            try:
                if w.response(self.sock.recv(2048)):
                    return w.ip
            except socket.timeout:
                pass
        return ""


def main():
    import argparse
    import random
    p = argparse.ArgumentParser(
        description="Fetch external IPv4 address using STUN",
        epilog="The default STUN port is %d." % STUN_PORT,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument(
        "-a", "--address", default="0.0.0.0",
        help="source address")
    p.add_argument(
        "-m", "--max-tries", default=10, type=int,
        help="max tries to send a STUN request")
    p.add_argument(
        "-t", "--timeout", default=0.5, type=float,
        help="socket timeout (in seconds) per request attempt")
    p.add_argument(
        "-V", "--version", action="version",
        version="%%(prog)s %s" % __version__)
    p.add_argument(
        "server", default=random.choice(STUN_SERVERS),
        nargs="?", help="STUN server[:port]")
    args = p.parse_args()

    if not args.address:
        p.error("invalid empty source address")

    if ":" not in args.server:
        args.server += ":%d" % STUN_PORT
    daddr, dport = args.server.strip().split(":")[:2]
    if not daddr:
        p.error("invalid empty server address")
    try:
        dport = int(dport)
    except ValueError:
        p.error("invalid server port '%s'" % dport)
    if not 0 < dport <= 65535:
        p.error("server port must be 0 < %d <= 65535" % dport)

    stun = StunIP(args.address, args.timeout, args.max_tries)
    ip = stun.ip(daddr, dport)
    if ip:
        print(ip)
        return 0
    return 1


if __name__ == "__main__":
    from signal import signal, SIGPIPE, SIG_DFL
    signal(SIGPIPE, SIG_DFL)  # Suppress broken pipe exceptions.
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(1)
