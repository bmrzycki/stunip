#!/usr/bin/env python

import socket
import struct
import sys
import uuid

__author__     = "Brian Rzycki"
__copyright__  = "Copyright 2020, Brian Rzycki"
__credits__    = [ "Brian Rzycki" ]
__license__    = "Apache-2.0"
__version__    = "1.0.0"
__maintainer__ = "Brian Rzycki"
__email__      = "brzycki@gmail.com"
__status__     = "Production"


class WireFormat(object):
    "https://tools.ietf.org/html/rfc3489"
    def __init__(self):
        self.id = uuid.uuid4().bytes
        self.ip = ''

    def reset(self):
        self.ip = ''

    def request(self):
        # A STUN header contains a Message Type, Message Length, and
        # a Transaction ID. The shortest and simplest request type is
        # a Binding Request (0x0001) with a Message Length of 0.
        self.reset()
        return struct.pack('!HH16s', 0x0001, 0, self.id)

    def response(self, buf):
        if self.ip:
            return True

        # The buffer must contain the following bytes: STUN Header (20),
        # MAPPED-ADDRESS Header (4), and a MAPPED-ADDRESS Value (8).
        if len(buf) < 32:
            return False

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
        # A Binding Response (0x0101) is the only valid STUN packet for the
        # Binding Request we sent. The Transaction ID must match the ID
        # sent in the Binding Request.
        stun_type, stun_len, stun_id = struct.unpack('!HH16s', buf[:20])
        if stun_type != 0x0101 or stun_id != self.id:
            return False

        # Sanity check: Attribute payload is Message Length bytes.
        attrs = buf[20:]
        if stun_len != len(attrs):
            return False

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
        attr_type, value_len = struct.unpack('!HH', attrs[:4])
        if attr_type != 0x0001 or value_len != 8:
            return False
        value = attrs[4:4+value_len]

        #  0                   1                   2                   3
        #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |  (Alignment)  |    Family     |           Port                |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                             Address                           |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # The Alignment byte and the Port in a MAPPED-ADDRESS Value are
        # ignored for our use-case. The RFC states Family is always 1.
        _, family, _, address = struct.unpack('!BBH4s', value)
        if family != 1:
            return False

        # Convert byte array Address into an IPv4 dotted-decimal string.
        try:
            ip = socket.inet_ntoa(address)
        except:
            return False

        self.ip = ip
        return True


class StunIP(object):
    def __init__(self, saddr='0.0.0.0', sport=0, timeout=0.5, max_tries=10):
        self.max_tries = max_tries
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(timeout)
        self.sock.bind((saddr, sport))

    def ip(self, addr, port=3478):
        w = WireFormat()
        for _ in range(self.max_tries):
            self.sock.sendto(w.request(), (addr, port))
            try:
                if w.response(self.sock.recv(2048)):
                    return w.ip
            except socket.timeout:
                pass
        return ''


def main():
    import argparse
    p = argparse.ArgumentParser(
        description='Fetch external IPv4 address using STUN',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument('-a', '--address', default='0.0.0.0:0',
                   help='source address[:port]')
    p.add_argument('-m', '--max-tries', default=10, type=int,
                   help='max tries to send a STUN request')
    p.add_argument('-t', '--timeout', default=0.5, type=float,
                   help='socket timeout (in seconds) per request attempt')
    p.add_argument('--version', action='version',
                   version='%%(prog)s %s-%s' % (__version__, __status__))
    p.add_argument('server', default='stun.stunprotocol.org:3478', nargs='?',
                   help='STUN server[:port]')
    a = p.parse_args()

    saddr, sport = (a.address, 0)
    if ':' in a.address:
        saddr, sport = a.address.split(':')[:2]
        try:
            sport = int(sport)
        except ValueError:
            p.error("invalid source port '%s'" % dport)
    daddr, dport = (a.server, 3478)
    if ':' in a.server:
        daddr, dport = a.server.split(':')[:2]
        try:
            dport = int(dport)
        except:
            p.error("invalid server port '%s'" % dport)

    stun = StunIP(saddr, sport, a.timeout, a.max_tries)
    ip = stun.ip(daddr, dport)
    if not ip:
        return 1
    print(ip)
    return 0


if __name__ == '__main__':
    # Suppress broken pipe exceptions.
    from signal import signal, SIGPIPE, SIG_DFL
    signal(SIGPIPE, SIG_DFL)
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(1)
