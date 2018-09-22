#!/usr/bin/python
#
# Simple SSSP client
#
# Copyright 2018 Andreas Thienemann <andreas@bawue.net>
#

import socket
import sys

class SSSPError(Exception):
  """Generic SSSPError Exception"""
  def __init__(self, msg=None):
    if msg is None:
      # Set some default useful error message
      msg = "An error occured during SSSP Processing"
    super(SSSPError, self).__init__(msg)

class sssp():
  def __init__(self, socket='/var/run/savdi/sssp.sock'):
    self.eicar = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    self.sssp_socket = socket
    self.sssp_version = 1.0
    self.connect()
    self.handshake()

  def connect(self):
    self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    self.s.settimeout(2)
    self.s.connect(self.sssp_socket)

  def recv_line(self):
    line = []
    maxwait = 15
    wait = 0
    while True:
      try:
        c = self.s.recv(1)
      except socket.timeout:
        if len(line) == 0:
          wait += 1
          continue
      line.append(c)
      if c == "\n":
          break
    return "".join(line)

  def recv_message(self):
    msg = []
    while True:
      l = self.recv_line().strip()
      if len(l) == 0:
        break
      msg.append(l)
    if len(msg) > 0:
      return "\n".join(msg)
    return ''

  def read_response(self, type="line"):
    resp = self.recv_line().strip()
    if resp.startswith('REJ'):
      self.handle_error(resp)
    return resp

  def send_command(self, command):
    self.s.send('{}\n'.format(command))
    return self.read_response(self)

  def handshake(self):
    resp = self.read_response()
    if not resp.startswith('OK SSSP'):
      raise SSSPError('Server not ready')
    if not resp.endswith('/{}'.format(self.sssp_version)):
      raise SSSPError('Server sent unexpected protocol version')
    return self.send_command('SSSP/{}'.format(self.sssp_version))

  def handle_error(self, msg):
    errors = {1: 'The request was not recognised.',
              2: 'The SSSP version number was incorrect.',
              3: 'There was an error in the OPTIONS list.',
              4: 'SCANDATA was trying to send too much data.',
              5: 'The request is not permitted.'
             }
    error = int(msg.split()[-1])
    raise SSSPError('The Server rejected our request: {}'.format(errors[error]))

  def send_data(self, data):
    self.s.sendall(data)
    return self.read_response()

  def query(self, type=''):
    msg = []
    msg.append(self.send_command('QUERY {}'.format(type)))
    msg.extend(self.recv_message().split('\n'))
    return [x for x in msg if len(x) > 0]
    
  def scandata(self, data):
    data_size = len(data)
    msg = []
    msg.append(self.send_command('SCANDATA {}'.format(data_size)))
    msg.append(self.send_data(data))
    msg.extend(self.recv_message().split('\n'))
    return [x for x in msg if len(x) > 0]

  def disconnect(self):
    self.send_command('BYE')
    self.s.close()

  def scan(self, data):
    virus = []
    fail = []
    ok = []
    done = []
    resp = self.scandata(data)
    self.disconnect()
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

if __name__ == "__main__":
  scanner = sssp()
  #print scanner.query('SERVER')
  with open(sys.argv[1], 'r') as f:
    print scanner.check(f.read())
