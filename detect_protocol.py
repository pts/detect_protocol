#! /usr/bin/python
# by pts@fazekas.hu at Sun Oct 21 09:16:49 CEST 2018

import struct


def detect_tcp_protocol(data):
  """Detects the network protocol by the first few bytes received.

  Also does some (but not comprehensive) data error checking, and if a
  data error was found, returns 'unknown'.

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
    if data[3] == '\0':
      return 'ssl2-client'
    else:
      return 'ssl23-client'
  elif c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':  # 'http-client' or 'ssh2'.
    i = 1
    while i < s and i <= 16 and data[i] in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
      i += 1
    if i == s:  # A ' ' or '-' is needed.
      return ''
    if i == 3 and data.startswith('SSH-'):  # `i == 3' is implied.
      if s < 9:
        if 'SSH-2.0-'.startswith(data):
          return ''
        return 'unknown'
      if data.startswith('SSH-2.0-'):
        return 'ssh2'  # Both SSH client and server send this prefix.
      return 'unknown'
    if i < 3 or i > 16:  # HTTP method name too long (arbitrary limit).
      return 'unknown'
    return 'http-client'
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
