# quic-socks
quic-socks implements socks5 server using custom protocol in the back end, due to the use of QUIC , 2x faster than shadowsocks, and safer.
## Features
* implements socks5 server in the front end for less RTT
* using custom protocol in the back end(client <-> server), only need 1 RTT
* client <-> server using TLS 1.3(QUIC)
* the experience will not deteriorate in the case of mobile networks(QUIC)
