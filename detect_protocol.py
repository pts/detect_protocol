#! /usr/bin/python
# by pts@fazekas.hu at Sun Oct 21 09:16:49 CEST 2018
#

import struct

PEEK_SIZE = 64
"""Minimum len(data) for which detect_tcp_protocol doesn't return ''."""

SUPPORTED_PROTOCOLS = (
    'tls-client',
    'ssl2-client',
    'ssl23-client',
    'http-client',  # HTTP/1.0 or HTTP/1.1 request to a server.
    'http-proxy-client',  # HTTP/1.0 or HTTP/1.1 request to a proxy.
    'ssh2',
    'smb-client',
    'x11-client',
    'rdp-client',
    'socks5-client',
    'uwsgi-client',  # Webserver connecting to uwsgi application server.
    'tinc-client',
    'xmpp',
    'adb-client',
    'scgi-client',  # Webserver connecting to SCGI application.
    'fastcgi-client',  # Webserver connecting to FastCGI application.
    'bittorrent-peer',
    'zmtp',  # ZeroMQ.
    'nanomsg-sp',  # nanomsg scalability protocol over TCP.
)
"""Sequence of protocol return values of detect_protocol."""


def _detect_uwsgi_client_protocol(data):
  """Helper function to detect 'uwsgi-client' only."""
  # Based on https://uwsgi-docs.readthedocs.io/en/latest/Protocol.html
  s = len(data)
  if ((s and data[0] not in '\x00\x06\x07\x08\x09\x0e') or
      (s > 3 and data[3] != '\0') or
      (s > 4 and data[4] < '\x06') or  # min(len('HTTP_?'), len('UWSGI_')).
      (s > 5 and data[5] != '\0') or
      (6 < s <= 11 and not 'HTTP_'.startswith(buffer(data, 6, 5)) and
                       not 'UWSGI'.startswith(buffer(data, 6, 5))) or
      (s >= 12 and 'HTTP_' != data[6 : 11] and
               not 'UWSGI_'.startswith(data[6 : 12]))
     ):
    # data[0] == '\x05' would be PSGI, but that conflicts with
    # 'socks5-client', e.g. if data == '\x05\x01\x01\x00\x20\x00HTTP_'. We
    # prioritize 'socks5-client' here.
    return 'unknown'
  if s >= 3:
    data_size, = struct.unpack('<H', data[1 : 3])
    if data_size < 8:
      return 'unknown'
  if s >= 6:
    key_size, = struct.unpack('<H', data[4 : 6])
    if key_size < 6 or data_size < key_size + 4:
      return 'unknown'
  if s < 12:
    return ''
  return 'uwsgi-client'


def _detect_nanomsg_sp_protocol(data):
  """Helper function to detect 'nanomsg-sp' only."""
  # Based on
  # https://github.com/nanomsg/nanomsg/blob/master/rfc/sp-tcp-mapping-01.txt
  # and
  # https://github.com/nanomsg/nanomsg/blob/master/rfc/sp-protocol-ids-01.txt
  s = len(data)
  if (not '\x00SP\x00'.startswith(buffer(data, 0, 4)) or
      (s > 4 and data[4] > '\1') or
      (s > 5 and data[4] == '\0' and data[5] < '\x10')):
    # data[4 : 5] is MDB-first of (protocol << 4 | endpoint), where
    # 1 <= protocol <= 31. Currently only 1 <= protocol <= 8 is assigned.
    return 'unknown'
  if s < 6:
    return ''
  return 'nanomsg-sp'


def _detect_adb_cnxn(data, i):
  """Helper function to detect 'adb-client' only from 'CNXN' at i."""
  # Based on
  # https://android.googlesource.com/platform/system/adb/+/master/protocol.txt
  s = len(data)
  if ((s > i and not 'CNXN'.startswith(buffer(data, i, 4))) or
      (s > i + 12 and data[i + 12] < '\x06') or
      (s > i + 13 and not '\0\0\0'.startswith(buffer(data, i + 13, 3))) or
      (s > i + 20 and
       not '\xbc\xb1\xa7\xb1'.startswith(buffer(data, i + 20, 4))) or
      (s > i + 24 and not 'host:'.startswith(buffer(data, i + 24, 5)))):
    return 'unknown'
  if s < i + 29:
    return ''
  return 'adb-client'


def _detect_adb_with_empty_packet(data):
  """Helper function to detect 'adb-client' starting with empty packet."""
  s = len(data)
  if data[:20].lstrip('\0') or data[20 : 24].lstrip('\xff'):
    return 'unknown'
  if s < 25:
    return ''
  return _detect_adb_cnxn(data, 24)


def detect_tcp_protocol(data):
  """Detects the network protocol by the first few bytes received.

  Also does some (but not comprehensive) data error checking, and if a
  data error was found, returns 'unknown'.

  Args:
    data: str or buffer containing the first few bytes received on an
        incoming TCP connection. Can be a prefix of a record.
  Returns:
    A string describing the application-level protocol spoken by the peer
    (one of SUPPORTED_PROTOCOLS), or 'unknown' if no protocol was recognized
    (or the peer has sent invalid data), or '' if more data has to be read
    to determine the answer. Tries very hard to use all information in
    `data', and returns '' only if `data' is really too short.
  """
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
    # TODO(pts): Make PEEK_SIZE smaller, don't read the entire vf_size.
    if s < min(64, vf_size + 11):  # Keep small buffer (64 bytes).
      return ''
    return ('ssl23-client', 'ssl2-client')[data[3] == '\0']
  elif c == 'l':  # 'x11-client' LSB-first.
    # ``Connection Setup'' in
    # https://www.x.org/releases/X11R7.5/doc/x11proto/proto.pdf
    if s < 6 and 'l\0\x0b\0\0\0'.startswith(data):
      return ''
    elif s >= 6 and data[:6] == 'l\0\x0b\0\0\0':
      return 'x11-client'
    else:
      return 'unknown'
  elif c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':  # 'http-client' or 'http-proxy-client' or 'ssh2' or 'x11-client' MSB-first or 'adb-client'.
    if c == 'C':  # Starts with 'CNXN'.
      protocol = _detect_adb_cnxn(data, 0)
      if protocol != 'unknown':
        return protocol
    i = 1
    while i < s and i <= 16 and data[i] in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
      i += 1
    if i == s:  # A ' ' or '-' is needed.
      return ''
    elif i == 1 and data[:2] == 'B\0':
      if s < 6 and 'B\0\0\x0b\0\0'.startswith(data):
        return ''
      elif s >= 6 and data[:6] == 'B\0\0\x0b\0\0':
        return 'x11-client'
      else:
        return 'unknown'
    elif i == 3 and data[:4] == 'SSH-':
      if s < 9:
        if 'SSH-2.0-'.startswith(data):
          return ''
        return 'unknown'
      if data[:8] == 'SSH-2.0-':
        return 'ssh2'  # Both SSH client and server send this prefix.
      return 'unknown'
    elif i < 3 or i > 16:  # HTTP method name too long (arbitrary limit).
      return 'unknown'
    elif not data[i].isspace():
      return 'unknown'
    else:
      # TODO(pts): Should we be more strict with HTTP method names (i.e.
      #            have a whitelist)?
      i += 1
      while i < s and data[i].isspace():
        i += 1
      if i == s:
        return ''
      elif data[i] == '/':
        # Based on
        # https://wiki.theory.org/index.php/BitTorrentSpecification#Tracker_HTTP.2FHTTPS_Protocol
        # : requests from the bittorrent client to the bittorrent tracker
        # can use a binary UDP protocol or HTTP(S). We report the latter as
        # 'http-client' here, since there is no foolproof way to distinguish it
        # from a HTTP GET request. We could detect the presence of info_hash=,
        # peer_id= etc. HTTP URL parameters, but it's tricky to do in 64 bytes.
        return 'http-client'
      else:
        return 'http-proxy-client'
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
  elif c == '\x05':  # 'socks5-client'.
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
  elif c == '\0':  # 'smb-client' or 'uwsgi-client' or 'adb-client' or 'nanomsg-sp'.
    # No real conflict, because:
    #
    # * If data[4] == '\x00' and data[5] == '\x00', then it's 'adb-client'.
    # * If data[4] == '\x00' and data[5] >= '\x10', then it's 'nanomsg-sp'.
    # * If data[4] == '\x01' and data[5] is any,    then it's 'nanomsg-sp'.
    # * if data[4] >= '\x06' and data[5] == '\x00', then it's 'uwsgi-client'.
    # * If data[4] == '\xff' and data[5] == 'S',    then it's 'smb-client'.
    #
    # We wouldn't be able to match openvpn-client though (/^\x00[\x0D-\xFF]/),
    # because it conflicts with 'uwsgi-client'.
    #
    # TODO(pts): Add a flag to disable 'smb-client', 'uwsgi-client' and
    # 'adb-client', so that we can enable 'openvpn-client', which starts with
    # '\0'.
    protocol = _detect_uwsgi_client_protocol(data)
    if protocol != 'unknown':
      return protocol
    protocol = _detect_adb_with_empty_packet(data)
    if protocol != 'unknown':
      return protocol
    protocol = _detect_nanomsg_sp_protocol(data)
    if protocol != 'unknown':
      return protocol
    # This is SMB over TCP, typically on port 445, as used by smbclient(1).
    # (The alternative is SMB over NetBIOS (NBT) over TCP, typically on ports
    # 137 and 139, and we are not able to detect it.)
    if ((s > 1 and data[1] != '\0') or
        # 'r' is SMB_COM_NEGOTIATE == 0x72.
        # '\0\0\0\0' is SMB_ERROR.
        (s > 4 and s < 13 and
         not '\xffSMBr\0\0\0\0'.startswith(buffer(data, 4, 9))) or
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
  elif c in '\x06\x07\x08\x09\x0e':
    return _detect_uwsgi_client_protocol(data)
  elif c == '0':
    if s < 2:
      return ''
    elif data[1] != ' ':
      return 'unknown'
    else:
      return 'tinc-client'
  elif c in '123456789':  # 'scgi-client'.
    # Based on https://en.wikipedia.org/wiki/Simple_Common_Gateway_Interface
    data = buffer(data, 0, 64)
    i = 1
    while i < s and data[i].isdigit():
      i += 1
    if i == s:
      return ''
    if data[i] != ':':
      return 'unknown'
    elif int(data[:i]) < 7:  # len('SCGI\x001\x00') == 7.
      return 'unknown'
    else:
      return 'scgi-client'
  elif c == '<':  # 'xmpp' (Jabber).
    # Based on https://xmpp.org/rfcs/rfc6120.html
    if (not '<?xml'.startswith(buffer(data, 0, 5)) or
        (s > 5 and not data[5].isspace() and data[5] != '?')):
      return 'unknown'
    # TODO(pts): Do we need 128? Then also update PEEK_SIZE.
    data = data[:64]  # Also converts to string.
    i = data.find('>', 6)
    if i < 0:
      return ''
    if data[i - 1] != '?':
      return 'unknown'
    i += 1
    while i < s and data[i].isspace():
      i += 1
    if i == s:
      return ''
    if not '<stream:stream'.startswith(buffer(data, i, 14)):
      return 'unknown'
    i += 14
    if i >= s:
      return ''
    if not data[i].isspace():
      return 'unknown'
    return 'xmpp'
  elif c == '\x01':  # 'fastcgi-client' or 'zmtp'.
    # Based on https://rfc.zeromq.org/spec:13/ZMTP/
    # Please note that non-anonymous ZMTP/1.0 peers are not supported.
    if s > 1 and data[1] == '\x00':
      return 'zmtp'
    # Based on https://fast-cgi.github.io/spec
    if ((s > 1 and data[1] not in '\x01\x09') or
        (s > 3 and data[1] == '\x01' and data[2 : 4] == '\0\0') or  # FCGI_BEGIN_REQUEST
        (s > 2 and data[1] == '\x09' and not '\0\0'.startswith(buffer(data, 2, 2)))):  # FCGI_GET_VALUES
      return 'unknown'
    if s < 4:
      return ''
    # data[2 : 4] is MSB-first, but we don't need it.
    return 'fastcgi-client'
  elif c == '\x13':  # 'bittorrent-peer':
    # Based on http://www.bittorrent.org/beps/bep_0003.html
    if not '\x13BitTorrent protocol'.startswith(buffer(data, 0, 20)):
      return 'unknown'
    elif s < 20:
      return ''
    else:
      return 'bittorrent-peer'
  elif c == '\xff':  # 'zmtp' ZMTP/2.0.
    # Based on https://rfc.zeromq.org/spec:15/ZMTP/
    if not '\xff\0\0\0\0\0\0\0\0\x7f'.startswith(buffer(data, 0, 10)):
      return 'unknown'
    elif s < 10:
      return ''
    else:
      return 'zmtp'
  else:
    return 'unknown'
