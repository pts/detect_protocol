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
    'GET ',
    'SSH ',
    'UNSUBSCRIBE ',
    'GET / HTTP/1.0\r\n',
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


def run_tests():
  detect_tcp_protocol = detect_protocol.detect_tcp_protocol
  for data in TLS_CLIENT_DATAS:
    for i in xrange(52):
      assert detect_tcp_protocol(data[:i]) == ''
    assert len(data) < 52 or detect_tcp_protocol(data) == 'tls-client'
  for data in SMB_CLIENT_DATAS:
    for i in xrange(41):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data) == 'smb-client'
  for data in SSH2_DATAS:
    for i in xrange(9):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data) == 'ssh2'
  for data in HTTP_CLIENT_DATAS:
    for i in xrange(data.find(' ') + 1):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data) == 'http-client'
  for data in SSL2_CLIENT_DATAS:
    for i in xrange(len(data)):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data) == 'ssl2-client'
  for data in SSL23_CLIENT_DATAS:
    for i in xrange(len(data)):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(buffer(data)) == 'ssl23-client'
  for data in X11_CLIENT_DATAS:
    for i in xrange(6):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data) == 'x11-client'
  for data in RDP_CLIENT_DATAS:
    for i in xrange(6):
      assert detect_tcp_protocol(data[:i]) == ''
    assert detect_tcp_protocol(data) == 'rdp-client'


if __name__ == '__main__':
  run_tests()
