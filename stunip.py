#!/usr/bin/env python

import socket
import struct
import sys
import uuid

__author__     = "Brian Rzycki"
__copyright__  = "Copyright 2020, Brian Rzycki"
__credits__    = [ "Brian Rzycki" ]
__license__    = "Apache-2.0"
__version__    = "1.1.0"
__maintainer__ = "Brian Rzycki"
__email__      = "brzycki@gmail.com"
__status__     = "Production"

STUN_PORT = 3478

class WireFormat(object):
    """
    Defined by the older https://tools.ietf.org/html/rfc3489 layout. We
    don't use the newer https://tools.ietf.org/html/rfc5389 to maximize
    server compatibility. All RFC 5389 servers must also handle RFC 3489.
    """
    def __init__(self):
        self.ip = ""
        self.id = b""

    def reset(self):
        self.ip = ""

        # Generate 15 random bits for the Transaction ID. RFC 5389 defines
        # the first 4 bytes (network byte order) as a new field called
        # "magic cookie". When set to 0x2112A442 the server expects the
        # client to comprehend the newer RFC 5389 format. Prevent this
        # by always setting the first byte to 0.
        self.id = b"\x00" + uuid.uuid4().bytes[:15]

    def request(self):
        # A STUN header contains a Message Type, Message Length, and
        # a Transaction ID. The shortest and simplest request type is
        # a Binding Request (0x0001) with a Message Length of 0.
        if not self.id:
            self.reset()
        return struct.pack("!HH16s", 0x0001, 0, self.id)

    def response(self, buf, cached=True):
        if cached and self.ip:
            return True
        self.ip = ""

        # The buffer must contain the following bytes: STUN Header (20),
        # MAPPED-ADDRESS Header (4), and a MAPPED-ADDRESS Value (8). There
        # may be more bytes if the server uses RFC 5389.
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
        # MAPPED-ADDRESS (0x0001) with a fixed Value Length of 8 bytes.
        attr_type, value_len = struct.unpack("!HH", attrs[:4])
        if attr_type != 0x0001 or value_len != 8:
            return False

        # We explicitly limit the size of value because the newer RFC 5389
        # may add additional attributes of no use to obtaining Address.
        value = attrs[4:4+value_len]

        # ================ MAPPED-ADDRESS Value (8 bytes) =================
        #  0                   1                   2                   3
        #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |  (Alignment)  |    Family     |           Port                |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                             Address                           |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # Alignment and Port ignored for our case and the RFC states Family
        # is always 1, corresponding to IPv4.
        _, family, _, address = struct.unpack("!BBH4s", value)
        if family != 1:
            return False

        try:
            # Convert Address bytes into an IPv4 dotted-decimal string.
            ip = socket.inet_ntoa(address)
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
        self.sock.bind((saddr, 0))  # Request dynamic source port

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
    p = argparse.ArgumentParser(
        description="Fetch external IPv4 address using STUN",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("-a", "--address", default="0.0.0.0",
                   help="source address")
    p.add_argument("-m", "--max-tries", default=10, type=int,
                   help="max tries to send a STUN request")
    p.add_argument("-t", "--timeout", default=0.5, type=float,
                   help="socket timeout (in seconds) per request attempt")
    p.add_argument("--version", action="version",
                   version="%%(prog)s %s-%s" % (__version__, __status__))
    p.add_argument("server", default="stun.stunprotocol.org:%d" % STUN_PORT,
                   nargs="?", help="STUN server[:port]")
    a = p.parse_args()

    if ":" in a.server:
        daddr, dport = a.server.split(":")[:2]
        try:
            dport = int(dport)
        except ValueError:
            p.error("invalid server port '%s'" % dport)
        if not 0 < dport <= 65535:
            p.error("server port must be 0 < %d <= 65535" % dport)
    else:
        daddr, dport = (a.server, STUN_PORT)

    if not a.address:
        p.error("invalid empty source address")
    if not daddr:
        p.error("invalid empty server address")

    stun = StunIP(a.address, a.timeout, a.max_tries)
    ip = stun.ip(daddr, dport)
    if ip:
        print(ip)
        return 0
    return 1


if __name__ == "__main__":
    # Suppress broken pipe exceptions.
    from signal import signal, SIGPIPE, SIG_DFL
    signal(SIGPIPE, SIG_DFL)
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(1)
