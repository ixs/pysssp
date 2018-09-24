#!/usr/bin/python
#
# Simple SSSP client
#
# Copyright 2018 Andreas Thienemann <andreas@bawue.net>
#

import pprint
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
  def __init__(self, socket='/var/run/savdi/sssp.sock'):
    self.eicar = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    self.sssp_socket = socket
    self.sssp_version = 1.0
    self.timeout = 2
    self.maxwait = 30
    if self.maxwait < self.timeout:
      self.maxwait = self.timeout
    self.connect()
    self._handshake()

  def connect(self):
    self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    self.s.settimeout(self.timeout)
    self.s.connect(self.sssp_socket)

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

  def query(self, type=''):
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

  def savi_opts(self):
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

    resp = self.query('SAVI')
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
    done, ok, fail, virus = self.scan(data)
    _, state, code, msg = done[-1].split(' ', 3)
    if code == '0000':
      return (True, 'Message is clean')
    elif code == '0203':
      return (False, 'Message is infected with {}'.format(", ".join(virus)))
    else:
      return (True, 'Unknown error')

  def selftest(self):
    res, msg = self.check(self.eicar)
    if res or not 'EICAR-AV-Test' in msg:
      raise SSSPError('Selftest failed. EICAR Virus was not detected.')
    return True

if __name__ == "__main__":
  scanner = sssp()
  scanner.set_options([{'savists': 'BehaviourSuspicious 1'}])
  scanner.set_options([{'savigrp': 'GrpSuper 1'}])
  pprint.pprint(scanner.savi_opts())
  print scanner.selftest()
  with open(sys.argv[1], 'r') as f:
    print(scanner.check(f.read()))
  scanner.disconnect()
