# stunip
Obtain an externally routable IPv4 address using the [STUN protocol](
https://tools.ietf.org/html/rfc3489) over UDP. Small home and private
networks often use [private IPv4 network address](
https://en.wikipedia.org/wiki/Private_network#Private_IPv4_addresses).
Applications like [Dynamic DNS](http://www.duckdns.org/) which require
the external Internet routable address mapped to this private network.
Most users rely on the HTTP/HTTPS protocols and websites like
https://ifconfig.co/.

STUN offers a lightweight alternative requiring fewer than 100 bytes
sent and received via UDP making STUN a great choice for embedded or
lower-end compute devices.

## Installation

`stunip.py` is self-contained and only needs Python 2.7+. The simplest
use-case is to `git clone` this repo and run directly.

## Servers

If no server is specified a random Google public STUN server will be used.
However, there are many other servers which may be faster depending on your
geographical region and you can find a list of public STUN servers
[here](https://gist.github.com/mondain/b0ec1cf5f60ae726202e).
