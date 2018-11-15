#! /usr/bin/python
# by pts@fazekas.hu at Sun Oct 21 09:16:49 CEST 2018
#
# TODO(pts): Add support for openvpn, tinc, adb, socks5
#            based on https://github.com/yrutschle/sslh/blob/master/probe.c

import struct

PEEK_SIZE = 776  # Longest for 'ssl2-client'.
"""Minimum len(data) for which detect_tcp_protocol doesn't return ''."""


def detect_tcp_protocol(data):
  """Detects the network protocol by the first few bytes received.

  Also does some (but not comprehensive) data error checking, and if a
  data error was found, returns 'unknown'.

  Supported protocols (return values) are: 'tls-client', 'ssl2-client',
  'ssl23-client', 'http-client', 'ssh2', 'smb-client'.

  Args:
    data: str or buffer containing the first few bytes received on an
        incoming TCP connection. Can be a prefix of a record.
  Returns:
    A string describing the application-level protocol spoken by the peer,
    or 'unknown' if no protocol was recognized (or the peer has sent invalid
    data), or '' if more data has to be read to determine the answer.
    Tries very hard to use all information in `data', and returns '' only if
    `data' is really too short.
  """
  # TODO(pts): Add detection of bittorrent and encrypted bittorrent.
  # TODO(pts): Add detection of OpenVPN: https://github.com/yrutschle/sslh/blob/d6c714166a9769eb8896adc3b9f012b5549d85f4/example.cfg#L91 and https://github.com/yrutschle/sslh/blob/d6c714166a9769eb8896adc3b9f012b5549d85f4/probe.c#L153
  # TODO(pts): Add detection of Wireguard.
  # TODO(pts): Add detection of Tinc VPN: https://github.com/yrutschle/sslh/blob/d6c714166a9769eb8896adc3b9f012b5549d85f4/probe.c#L168
  # TODO(pts): Add detection of Jabber: smarter than https://github.com/yrutschle/sslh/blob/d6c714166a9769eb8896adc3b9f012b5549d85f4/probe.c#L180
  # TODO(pts): Should we be more strict with HTTP method names (i.e. have a whitelist)?
  # TODO(pts): Add detection of ADB protocol: https://github.com/yrutschle/sslh/blob/d6c714166a9769eb8896adc3b9f012b5549d85f4/probe.c#L252
  # TODO(pts): Add detection of SOCKS5 protocol: https://github.com/yrutschle/sslh/blob/d6c714166a9769eb8896adc3b9f012b5549d85f4/probe.c#L291
  if not data:
    return ''
  c, s = data[0], len(data)
  if c == '\x16':  # 'tls-client'.
    if ((s > 1 and data[1] != '\x03') or  # Protocol version MSB.
        (s > 2 and data[2] > '\x07') or  # Protocol version LSB. \x07 would be TLS 1.6.
        (s > 4 and data[3] == '\0' and data[4] < '\x2f') or  # Record payload size smaller than 47.
        (s > 5 and data[5] != '\x01') or  # Message type ``client hello'' expected.
        (s > 6 and data[6] != '\0') or  # High byte of payload size must be 0.
        (s > 9 and data[9] != '\x03') or  # Protocol version MSB.
        (s > 10 and data[10] > '\x07')):  # Protocol version LSB. \x07 would be TLS 1.6.
      return 'unknown'
    if s >= 9:
      record_payload_size, = struct.unpack('>H', data[3 : 5])  # We had up to 290 bytes, or 512 bytes.
      payload_size, = struct.unpack('>H', data[7 : 9])
      if payload_size != record_payload_size - 4:
        return 'unknown'
    if s == 8:  # Fail 1 byte earlier.
      record_payload_size, = struct.unpack('>H', data[3 : 5])  # We had up to 290 bytes, or 512 bytes.
      if ord(data[7]) != ((record_payload_size - 4) >> 8):
        return 'unknown'
    if s < 52:
      return ''
    return 'tls-client'  # Typically https:// client.
  elif c in '\x80\x81':  # 'ssl2-client' or 'ssl23-client'.
    if ((s > 1 and (data[0] == '\x80' and data[1] < '\x10')) or  # LSB of size of SSL record.
        (s > 2 and data[2] != '\x01') or  # Message type ``client hello'.
        (s >= 5 and data[3 : 5] not in ('\x00\x02', '\x03\x00', '\x03\x01')) or  # Client version.
        (s > 5 and data[5] != '\0') or  # MSB of size of cipher-specs.
        (s > 6 and (data[6] == '\0' or ord(data[6]) % 3 != 0)) or  # LSB of size of cipher-specs.
        (s > 7 and data[7] != '\0') or  # MSB of size of session ID.
        (s > 8 and data[8] not in '\x00\x10') or  # LSB of size of session ID.
        (s > 9 and data[9] != '\0')):  # MSB of size of challenge.
      return 'unknown'
    if s < 11:
      return ''
    vf_size = ord(data[6]) + ord(data[8]) + ord(data[10])
    if ord(data[0]) << 8 | ord(data[1]) != vf_size + 0x8009:
      return 'unknown'  # Variable-width field sizes don't match.
    if s < vf_size + 11:
      return ''
    return ('ssl23-client', 'ssl2-client')[data[3] == '\0']
  elif c == 'l':  # 'x11-client' LSB-first.
    # ``Connection Setup'' in
    # https://www.x.org/releases/X11R7.5/doc/x11proto/proto.pdf
    if s < 6 and 'l\0\x0b\0\0\0'.startswith(data):
      return ''
    elif s >= 6 and data.startswith('l\0\x0b\0\0\0'):
      return 'x11-client'
    else:
      return 'unknown'
  elif c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':  # 'http-client' or 'ssh2' or 'x11-client' MSB-first.
    i = 1
    while i < s and i <= 16 and data[i] in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
      i += 1
    if i == s:  # A ' ' or '-' is needed.
      return ''
    elif i == 1 and data.startswith('B\0'):
      if s < 6 and 'B\0\0\x0b\0\0'.startswith(data):
        return ''
      elif s >= 6 and data.startswith('B\0\0\x0b\0\0'):
        return 'x11-client'
      else:
        return 'unknown'
    elif i == 3 and data.startswith('SSH-'):  # `i == 3' is implied.
      if s < 9:
        if 'SSH-2.0-'.startswith(data):
          return ''
        return 'unknown'
      if data.startswith('SSH-2.0-'):
        return 'ssh2'  # Both SSH client and server send this prefix.
      return 'unknown'
    elif i < 3 or i > 16:  # HTTP method name too long (arbitrary limit).
      return 'unknown'
    else:
      return 'http-client'
  elif c == '\x03':  # 'rdp-client'.
    # Based on xrdp-0.9.3.1/libxrdp/xrdp_iso.c.
    if s < 6:
      return ''
    elif (data[1] != '\0' or data[2] != '\0' or data[3] < '\x0b' or
          ord(data[3]) != ord(data[4]) + 5 or data[5] != '\xe0'):
      # Actually data[1] may be anything, data[2] may be '\1', clients other
      # than rdesktop may send such values.
      #
      # '\xe0' is ISO_PDU_CR (X.224 connection request).
      return 'unknown'
    else:
      return 'rdp-client'
  elif c == '\x05':  # 'socks5-client':
    # Based on
    # https://github.com/yrutschle/sslh/blob/8ec9799ca03e42a1cd38fd777a325751239067bc/probe.c#L288
    # and https://www.iana.org/assignments/socks-methods/socks-methods.xhtml
    if s < 2 or s < 2 + ord(data[1]):
      return ''
    elif (
        # Invalid number of authentication methods.
        data[1] == '\0' or ord(data[1]) > 10 or
        [1 for i in xrange(2, 2 + ord(data[1])) if ord(data[i]) > 9]):
      return 'unknown'
    else:
      return 'socks5-client'
  elif c == '\0':  # 'smb-client'.
    if ((s > 1 and data[1] != '\0') or
        # 'r' is SMB_COM_NEGOTIATE == 0x72.
        # '\0\0\0\0' is SMB_ERROR.
        (s > 4 and s < 13 and not '\xffSMBr\0\0\0\0'.startswith(data[4 : 13])) or
        (s >= 13 and data[4 : 13] != '\xffSMBr\0\0\0\0') or
        (s > 39 and data[39] != '\x02')):
      return 'unknown'
    if s >= 4:
      size1, = struct.unpack('>H', data[2 : 4])
      if size1 < 37:
        return 'unknown'
    if s >= 39:
      size2, = struct.unpack('<H', data[37 : 39])
      if size1 - size2 != 35:
        return 'unknown'
    if s < 41:
      return ''
    return 'smb-client'
  else:
    return 'unknown'
