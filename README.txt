detect_protocol: detect what protocol the TCP client is speaking
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
detect_protocol is a set of tools and libraries (currently implemented in
Python) which can be used to detect what application-level protocol the TCP
client is speaking, by peeking at the first few bytes it sends right after
the connection.

detect_protocol contains building blocks for
running multiple TCP services on the same port, but it's not a readily
working product yet. See the ``Similar projects'' list below for
alternatives.

Software components:

* detect_protocol.py contains the detect_tcp_protocol function which can
  detect a few TCP client protocols (e.g. HTTP, TLS, SSL, SSH and SMB
  (Samba, CIFS), X11). This file also has unit tests in
  detect_protocol_test.py.

* protocol_test.py contains some documentation and sample code explaining
  how and why the logic in detect_tcp_protocol works for the supported
  protocols.

* tcp_listen_peek_detect.py contains a demo TCP server which can peek at the
  first few bytes sent by the client (and detect the protocol by calling
  detect_tcp_protocol) without consuming those initial bytes. The
  non-consuming part is Linux-specific, and it's implemented by recv(...,
  MSG_PEEK) and epoll_ctl(..., EPOLLET | EPOLLIN | EPOLLRDHUP).

The clients of these protocols are impossible to detect because the client
expects the server to send some bytes first:

* SMTP
* FTP
* VNC

The clients of these protocols can't be detected reliably:

* OpenVPN: Not enough header fields to distinguish it from other protocols.
  https://github.com/yrutschle/sslh/blob/8ec9799ca03e42a1cd38fd777a325751239067bc/probe.c#L153
  tries to do it, but it is not reliable, because it relies on TCP
  buffering timing.

Similar projects:

* https://github.com/yrutschle/sslh written in C. It doesn't peek, but
  consumes the input bytes. It can also match on alpn_protocols and
  sni_hostnames for tls-client.
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
