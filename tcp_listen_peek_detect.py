#! /usr/bin/python
#
# tcp_listen_peek_detect.py: Detect TCP (sub)protocol without consuming bytes.
# by pts@fazekas.hu at Sun Oct 21 15:20:42 CEST 2018
#
# Related analysis: https://stackoverflow.com/a/8868593/97248
# See also tcp_listen_peek.py.
#

import select
import socket
import sys

import detect_protocol

if (not callable(getattr(select, 'epoll', None)) or
    getattr(select, 'EPOLLIN', None) != 1):
  raise RuntimeError('Linux with epoll support is needed.')

if getattr(select, 'EPOLLDRHUP', None) is None:
  # EPOLLRDHUP=0x2000 is only from Linux >= 2.6.17
  # We can't use EPOLLHUP or EPOLLPRI instead, they are not activated on
  # EOF.
  select.EPOLLRDHUP = 0x2000


def handle_sock(sock):
  peek_size = detect_protocol.PEEK_SIZE
  try:
    eofmask = select.EPOLLRDHUP | select.EPOLLHUP | select.EPOLLERR
    peek_size2 = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    print >>sys.stderr, 'ACCEPTED  %s' % peek_size2  # 1062000 on Linux 3.13.
    if peek_size2 < peek_size:
      # Linux 3.13 seems to ignore this call.
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, peek_size)
      peek_size2 = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
      print >>sys.stderr, 'ACCEPTED2 %s' % peek_size2
      if peek_size2 < peek_size:
        raise socket.error('Peek size too large.')
    ep = select.epoll(4)
    # EOF also counts as EPOLLIN, but in some cases of receiving an
    # EPOLLIN it's impossible to tell (withlout also asking for
    # EPOLLDRHUP) if there was an EOF: e.g. when we need a lot of time to
    # process the previous bytes, and in the meantime more bytes arrive
    # and maybe theres is also an EOF, so when call ep.poll() we'll notice
    # the extra bytes, but we won't know if there is an EOF.
    ep.register(sock.fileno(),
                select.EPOLLET | select.EPOLLIN | select.EPOLLRDHUP)
    while 1:
      print >>sys.stderr, 'POLL'
      events = ep.poll()
      print >>sys.stderr, 'EVENTS %s' % events
      # There is only a single event per fd, we counld just assert it.
      got_rdhup = sum(1 for event in events if event[1] & eofmask)
      if events:
        # Slow to copy prefix again.
        data = sock.recv(peek_size, socket.MSG_PEEK)
        print >>sys.stderr, 'PEEK %s' % [len(data), data]
        protocol = detect_protocol.detect_tcp_protocol(data)
        if protocol:
          break
        if len(data) >= peek_size:
          protocol = 'unknown-long'
          break
        if got_rdhup:
          protocol = 'unknown-eof'
          break  # EOF detected, using EPOLLRDHUP.
    print >>sys.stderr, 'DETECTED %r' % protocol
    while 1:
      data = sock.recv(8192)
      if not data:
        break
      print >>sys.stderr, 'GOT %s' % [len(data), data]
    print >>sys.stderr, 'EOF'
  finally:
    sock.close()


def main(argv):
  ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
  ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  ssock.bind(('127.0.0.1', 55555))
  ssock.listen(16)
  print >>sys.stderr, 'LISTEN %s' % [ssock.getsockname()]
  while 1:
    print >>sys.stderr, 'ACCEPT'
    sock, addr = ssock.accept()
    handle_sock(sock)
    del sock  # Save memory.


if __name__ == '__main__':
  sys.exit(main(sys.argv))
