#! /usr/bin/python
# by pts@fazekas.hu at Sun Oct 21 09:16:49 CEST 2018

import detect_protocol


TLS_CLIENT_DATAS = (
    '\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\xbb4\'\xc8\x1aTP',
    '\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\x91r\x0ez/\x91_.',
    '\x16\x03\x01\x00\xae\x01\x00\x00\xaa\x03\x03\x14\x9b\xa1\xf0',
    '\x16\x03\x00\x00{\x01\x00\x00w\x03\x00\x1d\xcc\xa3\x93.s\x98@\xe8e\xda\x90\xe9\x82\x8aO\x0b\xd8\xe59H\x8b\x80gHo\xe4HT\xd4d\xcb\x00\x00P\xc0\x14\xc0\n\x009\x008\x00\x88\x00\x87\xc0\x0f\xc0\x05\x005\x00\x84\xc0\x12\xc0\x08\x00\x16\x00\x13\xc0\r\xc0\x03\x00\n\xc0\x13\xc0\t\x003\x002\x00\x9a\x00\x99\x00E\x00D\xc0\x0e\xc0\x04\x00/\x00\x96\x00A\xc0\x11\xc0\x07\xc0\x0c\xc0\x02\x00\x05\x00\x04\x00\x15\x00\x12\x00\t\x00\xff\x01\x00',
    '\x16\x03\x01\x01"\x01\x00\x01\x1e\x03\x03!\xc6Bl9\x96oU|\xba\xf9\x16\x08\x8b\xe9C\xee\x87\x00\xcd\xaey\xb7\x18\xcb\xf4\x9d-\x9a\xe2-\xc8\x00\x00\x88\xc00\xc0,\xc0(\xc0$\xc0\x14\xc0\n\x00\xa3\x00\x9f\x00k\x00j\x009\x008\x00\x88\x00\x87\xc02\xc0.\xc0*\xc0&\xc0\x0f\xc0\x05\x00\x9d\x00=\x005\x00\x84\xc0\x12\xc0\x08\x00\x16\x00\x13\xc0\r\xc0\x03\x00\n\xc0/\xc0+\xc0\'\xc0#\xc0\x13\xc0\t\x00\xa2\x00\x9e\x00g\x00@\x003\x002\x00\x9a\x00\x99\x00E\x00D\xc01\xc0-\xc0)\xc0%\xc0\x0e\xc0\x04\x00\x9c\x00<\x00/\x00\x96\x00A\xc0\x11\xc0\x07\xc0\x0c\xc0\x02\x00\x05\x00\x04\x00\x15\x00\x12\x00\t\x00\xff\x01\x00\x00m\x00\x0b\x00\x04\x03\x00\x01\x02\x00\n\x004\x002\x00\x0e\x00\r\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\t\x00\n\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11\x00#\x00\x00\x00\r\x00 \x00\x1e\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03\x00\x0f\x00\x01\x01',
    '\x16\x03\x01\x00\xc6\x01\x00\x00\xc2\x03\x01*\xa5\x05P\x94\x92{\xf1\xc3\xfd.\xda\xec\xd8)\x0c\xa9\xa5:0\x96}\xe0Jfy-\x98\x0c\xe7\t\x89\x00\x00P\xc0\x14\xc0\n\x009\x008\x00\x88\x00\x87\xc0\x0f\xc0\x05\x005\x00\x84\xc0\x12\xc0\x08\x00\x16\x00\x13\xc0\r\xc0\x03\x00\n\xc0\x13\xc0\t\x003\x002\x00\x9a\x00\x99\x00E\x00D\xc0\x0e\xc0\x04\x00/\x00\x96\x00A\xc0\x11\xc0\x07\xc0\x0c\xc0\x02\x00\x05\x00\x04\x00\x15\x00\x12\x00\t\x00\xff\x01\x00\x00I\x00\x0b\x00\x04\x03\x00\x01\x02\x00\n\x004\x002\x00\x0e\x00\r\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\t\x00\n\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11\x00#\x00\x00\x00\x0f\x00\x01\x01',
    '\x16\x03\x00\x00T\x01\x00\x00P\x03\x00[\xcc<\xe5\x9b\xfc?\x06~15\xc3\x88\xf0\xa1Q\xe1\xfb\xae}\x19\xccJ\xb4~y\xef\xf4q\x89\tt\x00\x00(\x009\x008\x005\x00\x16\x00\x13\x00\n\x003\x002\x00/\x00\x05\x00\x04\x00\x15\x00\x12\x00\t\x00\x14\x00\x11\x00\x08\x00\x06\x00\x03\x00\xff\x02\x01\x00',
    '\x16\x03\x01\x00Z\x01\x00\x00V\x03\x01[\xcc<\xe5\xbf\x11\x13\xd7\xc7\x86\x11a\xb0!\xc7N\xb5\xa3\x8e\x9cq\x04\x19\x82\x17U\x02\x02\xe2b\xc9\xb6\x00\x00(\x009\x008\x005\x00\x16\x00\x13\x00\n\x003\x002\x00/\x00\x05\x00\x04\x00\x15\x00\x12\x00\t\x00\x14\x00\x11\x00\x08\x00\x06\x00\x03\x00\xff\x02\x01\x00\x00\x04\x00#\x00\x00',
)
SMB_CLIENT_DATAS = (
    '\x00\x00\x00\xbe\xffSMBr\x00\x00\x00\x00\x18C\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfe\xff\x00\x00\x00\x00\x00\x9b\x00\x02PC NETWORK PROGRAM 1.0\x00\x02MICROSOFT NETWORKS 1.03\x00\x02MICROSOFT NETWORKS 3.0\x00\x02LANMAN1.0\x00\x02LM1.2X002\x00\x02DOS LANMAN2.1\x00\x02LANMAN2.1\x00\x02Samba\x00\x02NT LANMAN 1.0\x00\x02NT LM 0.12\x00',
    '\x00\x00\x00\xd4\xffSMBr\x00\x00\x00\x00\x18C\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfe\xff\x00\x00\x00\x00\x00\xb1\x00\x02PC NETWORK PROGRAM 1.0\x00\x02MICROSOFT NETWORKS 1.03\x00\x02MICROSOFT NETWORKS 3.0\x00\x02LANMAN1.0\x00\x02LM1.2X002\x00\x02DOS LANMAN2.1\x00\x02LANMAN2.1\x00\x02Samba\x00\x02NT LANMAN 1.0\x00\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00',
)
SSH2_DATAS = (
    'SSH-2.0-MyClient\n',
)
HTTP_CLIENT_DATAS = (
    'GET  /',
    'SSH\t/',
    'UNSUBSCRIBE\f/',
    'GET / HTTP/1.0\r\n',
)
HTTP_PROXY_CLIENT_DATAS = (
    'GET http://example.org/foo HTTP/1.0\r\n',
    'CONNECT\t server.example.com:80 HTTP/1.1\r\n',
)
SSL2_CLIENT_DATAS = (
    '\x80+\x01\x00\x02\x00\x12\x00\x00\x00\x10\x07\x00\xc0\x03\x00\x80\x01\x00\x80\x06\x00@\x04\x00\x80\x02\x00\x80`\xb5\xcfv\xf7\x8al\xdedG\xd8\xf2\x8d\xaf\xa4/',
)
SSL23_CLIENT_DATAS = (
    '\x80g\x01\x03\x01\x00N\x00\x00\x00\x10\x00\x009\x00\x008\x00\x005\x00\x00\x16\x00\x00\x13\x00\x00\n\x07\x00\xc0\x00\x003\x00\x002\x00\x00/\x03\x00\x80\x00\x00\x05\x00\x00\x04\x01\x00\x80\x00\x00\x15\x00\x00\x12\x00\x00\t\x06\x00@\x00\x00\x14\x00\x00\x11\x00\x00\x08\x00\x00\x06\x04\x00\x80\x00\x00\x03\x02\x00\x80\x00\x00\xff\xaa+\x0b\x10\x95?y\x82\xef\xd0f\xaf\xc1\xe0\xa2<',
)
X11_CLIENT_DATAS = (
    '\x6c\x00\x0b\x00\x00\x00',
    '\x42\x00\x00\x0b\x00\x00',
)
RDP_CLIENT_DATAS = (
    '\x03\x00\x00\x29\x24\xe0',
)
SOCKS5_CLIENT_DATAS = (
    '\x05\x04\x06\x07\x09\x08',
)
UWSGI_CLIENT_DATAS = (
    '\x00\x0a\x00\x00\x06\x00HTTP_X',
    '\x06\x0a\x00\x00\x06\x00UWSGI_',
    '\x07\x03\x01\x00\xff\x00UWSGI_',
)
TINC_CLIENT_DATAS = (
    '0 ',
)
XMPP_DATAS = (
    '<?xml version=\'1.0\'?>\r\n<stream:stream\t',
    '<?xml version=\'1.0\'?>\r\n<stream:stream\n  version',
)
ADB_CLIENT_DATAS = (
    'CNXN\0\0\0\1\0\0\4\0\6\0\0\0????\xbc\xb1\xa7\xb1host::',
    '\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xff\xff\xff\xffCNXN\0\0\0\1\0\0\4\0\6\0\0\0????\xbc\xb1\xa7\xb1host::',
)
SCGI_CLIENT_DATAS = (
    '42:',
    '70:CONTENT_LENGTH\x0027\x00SCGI\x001\x00REQUEST_METHOD\x00POST\x00REQUEST_URI\x00/deepthought\x00,What is the answer to life?',
)
FASTCGI_CLIENT_DATAS = (
    '\1\1\0\1',
    '\1\x09\0\0',
)
BITTORRENT_PEER_DATAS = (
    '\x13BitTorrent protocol',
)
ZMTP_DATAS = (
    '\1\0',
    '\xff\0\0\0\0\0\0\0\0\x7f',
)
NANOMSG_SP_DATAS = (
    '\0SP\0\0\x10',
    '\0SP\0\0\x11',
    '\0SP\0\1\xff',
)
RTMP_DATAS = (
    '\3ABCD\0\0\0\0',
    '\3EFGH\x80\0\3\2',
)
MEMCACHED_CLIENT_DATAS = (
    'add x',
    'get\tx',
    'stats\r\n',
)
REDIS_CLIENT_INLINE_DATAS = (
    'PING\n',
    'PING\r\n',
    'CLIENT ID',
    'CLIENT\tID',
)
REDIS_CLIENT_DATAS = (
    '*2\r\n$6\r\nCLIENT\r\n$2\r\nID\r\n',
)
POSTGRESQL_CLIENT_DATAS = (
    '\0\0\0\x09\0\3\0\0\0',
    '\0\0\0\x13\0\3\0\0user\0root\0\0',
)
RSYNCD_CLIENT_DATAS = (
    '@RSYNCD: 30.0\n',
    '@RSYNCD: 31.0\n',
)

def detect_tcp_protocol(data):
  assert len(data) <= detect_protocol.PEEK_SIZE
  protocol = detect_protocol.detect_tcp_protocol(buffer(data))
  assert (protocol in detect_protocol.SUPPORTED_PROTOCOLS or
          protocol in ('', 'unknown')), 'Unknown protocol: %r' % (protocol,)
  return protocol


def run_tests():
  assert '' not in detect_protocol.SUPPORTED_PROTOCOLS
  assert 'unknown' not in detect_protocol.SUPPORTED_PROTOCOLS
  for data in TLS_CLIENT_DATAS:
    data = data[:52]
    for i in xrange(len(data)):
      assert detect_tcp_protocol(data[:i]) == ''
    assert len(data) < 52 or detect_tcp_protocol(data) == 'tls-client'
  for data in SMB_CLIENT_DATAS:
    for i in xrange(41):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data[:41]) == 'smb-client'
    assert detect_tcp_protocol(data[:64]) == 'smb-client'
  for data in SSH2_DATAS:
    for i in xrange(9):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data) == 'ssh2'
  for data in HTTP_CLIENT_DATAS:
    j = 0
    while not data[j].isspace():
      j += 1
    while data[j].isspace():
      j += 1
    j += 1
    for i in xrange(j):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data[:j]) == 'http-client'
    assert detect_tcp_protocol(data) == 'http-client'
  for data in HTTP_PROXY_CLIENT_DATAS:
    j = 0
    while not data[j].isspace():
      j += 1
    while data[j].isspace():
      j += 1
    j += 1
    for i in xrange(j):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data[:j]) == 'http-proxy-client'
    assert detect_tcp_protocol(data) == 'http-proxy-client'
  for data in SSL2_CLIENT_DATAS:
    for i in xrange(min(len(data), 64)):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data) == 'ssl2-client'
  for data in SSL23_CLIENT_DATAS:
    for i in xrange(min(len(data), 64)):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data[:64]) == 'ssl23-client'
  for data in X11_CLIENT_DATAS:
    for i in xrange(6):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data) == 'x11-client'
  for data in RDP_CLIENT_DATAS:
    for i in xrange(6):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data) == 'rdp-client'
  for data in SOCKS5_CLIENT_DATAS:
    for i in xrange(6):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data) == 'socks5-client'
  for data in UWSGI_CLIENT_DATAS:
    for i in xrange(12):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data) == 'uwsgi-client'
  for data in TINC_CLIENT_DATAS:
    for i in xrange(2):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data) == 'tinc-client'
  for data in XMPP_DATAS:
    j = data.find(':stream') + 8
    for i in xrange(j):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data[:j]) == 'xmpp'
    assert detect_tcp_protocol(data) == 'xmpp'
  for data in ADB_CLIENT_DATAS:
    for i in xrange(29):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data[:29 + data.find('CNXN')]) == 'adb-client'
    assert detect_tcp_protocol(data) == 'adb-client'
  for data in SCGI_CLIENT_DATAS:
    data = data[:64]
    for i in xrange(data.find(':') + 1):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data) == 'scgi-client'
  for data in FASTCGI_CLIENT_DATAS:
    for i in xrange(len(data)):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data) == 'fastcgi-client'
  for data in BITTORRENT_PEER_DATAS:
    for i in xrange(len(data)):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data) == 'bittorrent-peer'
  for data in ZMTP_DATAS:
    for i in xrange(len(data)):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data) == 'zmtp'
  for data in NANOMSG_SP_DATAS:
    for i in xrange(len(data)):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data) == 'nanomsg-sp'
  for data in MEMCACHED_CLIENT_DATAS:
    j = 0
    while not data[j].isspace():
      j += 1
    for i in xrange(j):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data[:j + 1]) == 'memcached-client'
    assert detect_tcp_protocol(data) == 'memcached-client'
  for data in REDIS_CLIENT_INLINE_DATAS:
    j = 0
    while not data[j].isspace():
      j += 1
    if data[j].isspace():
      j += 1
    for i in xrange(j):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data[:j + 1]) == 'redis-client-inline'
    assert detect_tcp_protocol(data) == 'redis-client-inline'
  for data in REDIS_CLIENT_DATAS:
    for i in xrange(data.find('\n')):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data[:data.find('\n') + 1]) == 'redis-client'
    assert detect_tcp_protocol(data) == 'redis-client'
  for data in POSTGRESQL_CLIENT_DATAS:
    for i in xrange(7):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data[:7]) == 'postgresql-client'
    assert detect_tcp_protocol(data) == 'postgresql-client'
  for data in RSYNCD_CLIENT_DATAS:
    for i in xrange(data.find(' ') + 1):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data[:data.find(' ') + 2]) == 'rsyncd-client'
    assert detect_tcp_protocol(data) == 'rsyncd-client'


if __name__ == '__main__':
  run_tests()
