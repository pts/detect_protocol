#! /usr/bin/python
# by pts@fazekas.hu at Sun Oct 21 15:20:42 CEST 2018
#
# Related analysis: https://stackoverflow.com/a/8868593/97248
#
# I ended up calling recv() with the flag MSG_PEEK. This will make the
# subsequent recv() or recvmsg() call in the library read the same data.
# Without the Linux-specific EPOLLET, I can use it to conveniently look
# ahead only a single byte. Let's suppose I needed to look ahead 2 bytes.
# I'd call recv(fd, buf, 2, MSG_PEEK). If 1 out of the 2 bytes have already
# arrived, then recv() would return immediately, no matter how many times I
# call it. So to wait for the 2nd byte, my only portable option is calling
# recv() in a busy, polling loop.
#
# To wait for the 2nd byte without polling, on Linux 2.6.17 or later I can
# use epoll_ctl with EPOLLIN | EPOLLET. If I want to know if there was an
# EOF afterwards, I need EOPLLIN | EPOLLET | EPOLLRDHUP. (Please note that
# EPOLLHUP won't be returned on EOF.)
#
# I've just verified on my Linux system that I can peek about 900 kB to the
# socket this way by default. (SO_RECVBUF is 1 MB for me by default,
# decreasing it with setsockopt seems to decrease how much can be received,
# but not by a consistent amount. Maybe I decrease it too late?)
#

import select
import socket
import sys

if (not callable(getattr(select, 'epoll', None)) or
    getattr(select, 'EPOLLIN', None) != 1):
  raise RuntimeError('Linux with epoll support is needed.')

if getattr(select, 'EPOLLDRHUP', None) is None:
  # EPOLLRDHUP=0x2000 is only from Linux >= 2.6.17
  # We can't use EPOLLHUP or EPOLLPRI instead, they are not activated on
  # EOF.
  select.EPOLLRDHUP = 0x2000


def handle_sock(sock, peek_size):
  try:
    eofmask = select.EPOLLRDHUP | select.EPOLLHUP | select.EPOLLERR
    peek_size2 = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    print >>sys.stderr, 'ACCEPTED %s' % peek_size2  # 1062000 on Linux 3.13.
    if peek_size2 < peek_size:
      # Linux 3.13 seems to ignore this call.
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, peek_size)
      peek_size2 = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
      if peek_size2 < peek_size:
        raise socket.error('Peek size too large.')
    print >>sys.stderr, 'ACCEPTED %s' % peek_size2  # 1062000 on Linux 3.13.
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
        pre = sock.recv(peek_size, socket.MSG_PEEK)
        print >>sys.stderr, 'GOT %r' % [len(pre), pre]
        if len(pre) >= peek_size:
          print >>sys.stderr, 'PEEK_TOO_LONG'
          break
        if got_rdhup:
          print >>sys.stderr, 'EOF'
          break  # EOF detected, using EPOLLRDHUP.
  finally:
    sock.close()


def main(argv):
  ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
  ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  ssock.bind(('127.0.0.1', 55555))
  ssock.listen(16)
  print >>sys.stderr, 'LISTEN %s' % [ssock.getsockname()]
  peek_size = 10
  while 1:
    print >>sys.stderr, 'ACCEPT'
    sock, addr = ssock.accept()
    handle_sock(sock, peek_size)
    del sock  # Save memory.


if __name__ == '__main__':
  sys.exit(main(sys.argv))
