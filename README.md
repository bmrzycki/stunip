# stunip
Obtain an external (NAT) IPv4 address using the [STUN protocol](https://tools.ietf.org/html/rfc3489) over UDP. This is
common for home networks which use a gateway router with a private IP network mapped to a valid Internet address.

A common method to identify one's external IP is to use websites like https://ifconfig.co/ and curl/wget. STUN offers a
lightweight alternative requiring no TCP setup or SSL for HTTPS traffic. The whole transmit and receive transaction uses
fewer than 100 bytes on the network.

## Installation

The code requires no installation or external libraries other than Python 2.7+. The `stunip.py` binary can be run from
the repo or copied to any path location.

## Usage

The default STUN server uses the publically available [STUNTMAN Open Source STUN server](http://stunprotocol.org/) but
there are many other servers which may be faster on your region. There an (admittedly older) list of public STUN servers
[here](https://gist.github.com/mondain/b0ec1cf5f60ae726202e).
