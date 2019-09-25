#!/usr/bin/python
#
# Python implementation of the Sophos SSSP protocol to interface with the
# Sophos SAVDI virus scanner daemon.
#
#   Copyright 2018,2019 Andreas Thienemann <andreas@bawue.net>
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

import pprint
import codecs
import socket
import sys

class SSSPError(Exception):
  """Generic SSSPError Exception"""
  def __init__(self, msg=None):
    if msg is None:
      # Set some default useful error message
      msg = "An error occured during SSSP Processing"
    super(SSSPError, self).__init__(msg)

class SSSPOptionError(SSSPError):
  """Generic SSSPOptionError Exception"""
  def __init__(self, msg=None):
    if msg is None:
      # Set some default useful error message
      msg = "An option could not be set"
    super(SSSPOptionError, self).__init__(msg)

class sssp():
  def __init__(self, sock='/var/run/savdi/sssp.sock'):
    # The eicar string is ROT13 encoded to prevent virus scanners from triggering a
    # false alarm
    self.eicar = "K5B!C%@NC[4\\CMK54(C^)7PP)7}$RVPNE-FGNAQNEQ-NAGVIVEHF-GRFG-SVYR!$U+U*"
    self.sssp_socket = sock
    self.sssp_version = 1.0
    self.timeout = 2
    self.maxwait = 30
    if self.maxwait < self.timeout:
      self.maxwait = self.timeout
    self.connect()
    self._handshake()

  def connect(self):
    """Connect to SSSP socket"""
    if self.sssp_socket[0] == '/':
      self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
      sock = self.sssp_socket
    elif self.sssp_socket.startswith('inet:'):
      self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      _, bind_host, port = self.sssp_socket.split(':')
      sock = (bind_host, int(port))
    elif isinstance(self.socket, tuple):
      self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock = self.sssp_socket

    self.s.settimeout(self.timeout)
    self.s.connect(sock)

  def _recv_line(self):
    line = []
    wait = 0
    while True:
      try:
        c = self.s.recv(1)
      except socket.timeout:
        if wait >= (self.maxwait / self.timeout):
          raise
        if len(line) == 0:
          wait += 1
          continue
      line.append(c)
      if c == "\n":
          break
    return "".join(line)

  def _recv_message(self):
    msg = []
    while True:
      l = self._recv_line().strip()
      if len(l) == 0:
        break
      msg.append(l)
    if len(msg) > 0:
      return "\n".join(msg)
    return ''

  def _read_response(self, type="line"):
    resp = self._recv_line().strip()
    if resp.startswith('ACC '):
      return ''
    if resp.startswith('REJ '):
      self._handle_error(resp)
    return resp

  def _send_command(self, command):
    self.s.send('{}\n'.format(command))
    return self._read_response(self)

  def _handshake(self):
    resp = self._read_response()
    if not resp.startswith('OK SSSP'):
      raise SSSPError('Server not ready')
    if not resp.endswith('/{}'.format(self.sssp_version)):
      raise SSSPError('Server sent unexpected protocol version')
    return self._send_command('SSSP/{}'.format(self.sssp_version))

  def _handle_error(self, msg):
    errors = {1: 'The request was not recognised.',
              2: 'The SSSP version number was incorrect.',
              3: 'There was an error in the OPTIONS list.',
              4: 'SCANDATA was trying to send too much data.',
              5: 'The request is not permitted.'
             }
    error = int(msg.split()[-1])
    raise SSSPError('The Server rejected our request: {}'.format(errors[error]))

  def _send_data(self, data, read_response=True):
    self.s.sendall(data)
    if read_response:
      return self._read_response()

  def _query(self, type=''):
    msg = []
    msg.append(self._send_command('QUERY {}'.format(type.upper())))
    msg.extend(self._recv_message().split('\n'))
    return [x for x in msg if len(x) > 0]

  def set_options(self, options):
    self._send_data('OPTIONS\n', False)
    for option in options:
      for k, v in option.items():
        self._send_data('{}: {}\n'.format(k, v), False)
    self._send_command('\n')
    resp = self._recv_message().split(' ', 3)
    if resp[1] == 'OK':
      return True
    else:
      raise SSSPOptionError(resp[3])

  def query_engine(self):
    resp = self._query('ENGINE')
    infos = {}
    vids = []
    vid = {}
    for l in resp:
      key, value = [x.strip() for x in l.split(':')]

      if key in ['date', 'filename', 'state', 'type']:
        if key in ['state', 'type']:
          value = int(value)

        vid.update({key: value})

        if key == 'type':
          vids.append(vid)
          vid = {}
      else:
        infos.update({key: value})
    infos.update({'virus_ids': vids})
    return infos

  def query_server(self):
    resp = self._query('SERVER')
    infos = {}
    for l in resp:
      key, value = [x.strip() for x in l.split(':')]
      infos.update({key: value})
    return infos

  def query_savi(self):
    types = {0: 'SOPHOS_TYPE_INVALID',
             1: 'SOPHOS_TYPE_U08',
             2: 'SOPHOS_TYPE_U16',
             3: 'SOPHOS_TYPE_U32',
             4: 'SOPHOS_TYPE_S08',
             5: 'SOPHOS_TYPE_S16',
             6: 'SOPHOS_TYPE_S32',
             7: 'SOPHOS_TYPE_BOOLEAN',
             8: 'SOPHOS_TYPE_BYTESTREAM',
             9: 'SOPHOS_TYPE_OPTION_GROUP',
             10: 'SOPHOS_TYPE_OPTION_STRING'}

    resp = self._query('SAVI')
    opts = {}
    opt = {}
    for l in resp:
      key, value = [x.strip() for x in l.split(':')]

      if key == 'type':
        value = int(value)
        try:
          opt.update({'named_type': types[value][12:]})
        except KeyError:
          opt.update({'named_type': 'TYPE{}'.format(value)})

      opt.update({key: value})

      if key == 'value':
        if opt['type'] > 0 and opt['type'] < 7:
          value = int(value)
        opts[opt['name']] = {'value': value, 'type': opt['named_type']}
    return opts

  def scandata(self, data):
    data_size = len(data)
    msg = []
    msg.append(self._send_command('SCANDATA {}'.format(data_size)))
    msg.append(self._send_data(data))
    msg.extend(self._recv_message().split('\n'))
    return [x for x in msg if len(x) > 0]

  def disconnect(self):
    self._send_command('BYE')
    self.s.close()

  def scan(self, data):
    virus = []
    fail = []
    ok = []
    done = []
    resp = self.scandata(data)
    virus.extend([x.split()[1] for x in resp if x.startswith('VIRUS ')])
    fail.extend([x.split()[1] for x in resp if x.startswith('FAIL ')])
    ok.extend([x.split()[1] for x in resp if x.startswith('OK ')])
    done.extend([x for x in resp if x.startswith('DONE ')])
    return (done, ok, fail, virus)

  def check(self, data):
    """Check a string for a virus"""
    done, ok, fail, virus = self.scan(data)
    _, state, code, msg = done[-1].split(' ', 3)
    if code == '0000':
      return (True, 'Message is clean')
    elif code == '0203':
      return (False, 'Message is infected with {}'.format(", ".join(virus)))
    else:
      return (True, 'Unknown error')

  def selftest(self):
    """Run a quick selftest on the savdi daemon.

    Send the eicar test string to the savdi socket and raise an exception if
    the report comes back clean.
    """
    res, msg = self.check(codecs.encode(self.eicar, 'rot_13'))
    if res or not 'EICAR-AV-Test' in msg:
      raise SSSPError('Selftest failed. EICAR Virus was not detected.')
    return True

if __name__ == "__main__":
  scanner = sssp()
  scanner.set_options([{'savigrp': 'GrpSuper 1'}])
  pprint.pprint(scanner.query_engine())
  pprint.pprint(scanner.query_server())
  with open(sys.argv[1], 'r') as f:
    print(scanner.check(f.read()))
  scanner.disconnect()
