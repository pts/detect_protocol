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

* Encrypted bittorrent protocol between peers (documented on
  http://wiki.vuze.com/w/Message_Stream_Encryption), because the first
  message looks like random garbage. (In fact it contiains Diffie--Hellman
  values and random padding.)

Similar projects:

* https://github.com/yrutschle/sslh
  Written in C. It doesn't peek, but
  consumes the input bytes. It can also match on alpn_protocols and
  sni_hostnames for tls-client.
* https://github.com/jamescun/switcher
  Written in Go.
  Contains dumb SSH detection and no fancy protocol detection.
* https://github.com/soheilhy/cmux
  A Go library, supports HTTP/1.x, HTTP/2, TLS, header matching (e.g.
  "content-type": "application/grpc") and prefix (e.g. SSH).
* https://github.com/stealth/sshttp
  Written in C++. Supports HTTP, HTTPS and SSH. Has a built-in HTTP server.
  Supports SNI for HTTPS.
* https://github.com/mscdex/httpolyglot
  Written in JavaScript for Node.js, supports only HTTP and HTTPS.
* https://github.com/shawnl/multiplexd
  Written in Go, supports SSH, HTTP, HTTPS and OpenVPN.
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
