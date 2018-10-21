detect_protocol: detect what protocol the TCP client is speaking
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
detect_protocol is a set of tools and libraries (currently implemented in
Python) which can be used to detect what application-level protocol the TCP
client is speaking, by peeking at the first few bytes it sends right after
the connection.

Software components:

* detect_protocol.py contains the detect_tcp_protocol function which can
  detect a few TCP client protocols (e.g. HTTP, TLS, SSL, SSH and SMB
  (Samba, CIFS)). This file also has unit tests in detect_protocol_test.py.

* protocol_test.py contains some documentation and sample code explaining
  how and why the logic in detect_tcp_protocol works for the supported
  protocols.

* tcp_listen_peek_detect.py contains a demo TCP server which can peek at the
  first few bytes sent by the client (and detect the protocol by calling
  detect_tcp_protocol) without consuming those initial bytes. The
  non-consuming part is Linux-specific, and it's implemented by recv(...,
  MSG_PEEK) and epoll_ctl(..., EPOLLET | EPOLLIN | EPOLLRDHUP).

Similar projects:

* https://github.com/yrutschle/sslh written in C. It doesn't peek, but
  consumes the input bytes.
* https://github.com/jamescun/switcher
* https://github.com/soheilhy/cmux
* https://github.com/stealth/sshttp
* https://github.com/mscdex/httpolyglot
* https://github.com/shawnl/multiplexd
* https://github.com/shawnl/nginx-ssh
* https://github.com/houkx/nettythrift
* https://github.com/robertklep/node-port-mux
* https://github.com/beatgammit/tcpmux
* https://github.com/typcn/sshrdp
* https://github.com/VishvendraRana/socket_multiplexer
* https://github.com/huaye2007/tcpwebsocket
* https://github.com/MarcosRZ/vhost-manager
* https://github.com/frxstrem/go-polyglot
* https://github.com/foursquare/finagle-dual
* Search for "same port" on GitHub.

__END__
