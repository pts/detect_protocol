#! /usr/bin/python
#
# tcp_listen_dump.py: Listen on TCP port, dump first few bytes received.
# by pts@fazekas.hu at Sun Oct 21 09:16:49 CEST 2018
#

import socket
import sys


def main(argv):
  saddr = ('127.0.0.1', 55555)
  ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
  ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  print >>sys.stderr, 'info: binding TCP socket to %r' % (saddr,)
  ssock.bind(saddr)
  ssock.listen(16)
  while 1:
    print >>sys.stderr, 'info: accepting'
    sock, addr = ssock.accept()
    try:
      print >>sys.stderr, 'info: got incoming connection from %r' % (addr,)
      sock.settimeout(3)
      data = None
      try:
        data = sock.recv(8192)
      except socket.timeout:
        data = ['timeout']
      except (IOError, OSError, socket.error), e:
        data = ['error', str(e)]
      print >>sys.stderr, 'info: received %r' % data
    finally:
      print >>sys.stderr, 'info: closing connection'
      sock.close()
    del sock


if __name__ == '__main__':
  sys.exit(main(sys.argv))
