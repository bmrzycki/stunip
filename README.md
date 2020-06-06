#-----------------------------------------------------------------------

# stunip
Obtain an externally routable IPv4 address using the [STUN protocol](
https://tools.ietf.org/html/rfc3489) over UDP. Small home and private
networks often use [private IPv4 network addresses](
https://en.wikipedia.org/wiki/Private_network#Private_IPv4_addresses).
Applications like [Dynamic DNS](http://www.duckdns.org/) require the
Internet routable address mapped to this private network.

Most users rely on http and websites like https://ifconfig.co/ to 
provide this mapping. STUN offers a lightweight alternative requiring
less network overhead with an entire transaction length less than
100 bytes. It also uses UDP which requires no TCP or HTTPS protocol
setup which means the entire process is very fast and uses almost no
CPU. It's a great choice for embedded or lower-end compute devices.

## Installation

The code requires no installation or external libraries other than
Python 2.7+. The `stunip.py` binary runs from any path location.  The
simplest method is to `git clone` the repo and run directly.

## Servers

The  [STUNTMAN Open Source STUN server](http://stunprotocol.org/) is the
default server. However, there are many other servers which may be faster
depending on your geographical region. You can find a list of public STUN
servers [here](https://gist.github.com/mondain/b0ec1cf5f60ae726202e).
