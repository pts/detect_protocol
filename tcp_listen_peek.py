#! /usr/bin/python
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


def main(argv):
  ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
  ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  ssock.bind(('127.0.0.1', 55555))
  ssock.listen(16)
  print >>sys.stderr, 'LISTEN %s' % [ssock.getsockname()]
  while 1:
    print >>sys.stderr, 'ACCEPT'
    sock, addr = ssock.accept()
    try:
      print >>sys.stderr, 'ACCEPTED %s' % sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)  # 1062000
      #sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 10000)
      ep = select.epoll(4)
      # EOF also counts as EPOLLIN.
      # ep.register(sock.fileno(), select.EPOLLET | select.EPOLLIN)
      # If we don't specify EPOLLDRHUP here, EOF won't be detected.
      ep.register(sock.fileno(), select.EPOLLET | select.EPOLLIN | select.EPOLLRDHUP | select.EPOLLPRI | select.EPOLLHUP)
      while 1:
        print >>sys.stderr, 'POLL'
        events = ep.poll()
        print >>sys.stderr, 'EVENTS %s' % events
        if events:
          # !! maximum buffer size should be: 942927 or 963019
          pre = sock.recv(1 << 25, socket.MSG_PEEK)
          #print >>sys.stderr, [len(pre), pre, len(pre)]
          print >>sys.stderr, 'GOT %r' % [prev_size, len(pre), pre]
          if events[0][1] & (select.EPOLLRDHUP | select.EPOLLHUP | select.EPOLLERR):
            break  # EOF detected, using EPOLLRDHUP.
    finally:
      sock.close()


if __name__ == '__main__':
  sys.exit(main(sys.argv))
