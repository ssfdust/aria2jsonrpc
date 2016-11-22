#!/usr/bin/env python3

# -*- coding: utf8 -*-

# Copyright (C) 2012-2014 Xyne
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# (version 2) as published by the Free Software Foundation.
#
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import base64
import http.client
import json
import urllib.parse
import urllib.request
import ssl

################################## Constants ###################################

DEFAULT_PORT = 6800
SERVER_URI_FORMAT = '{}://{}:{:d}/jsonrpc'



############################ Convenience Functions #############################

def to_json_list(obj):
  '''
  Wrap strings in lists. Other iterables are converted to lists directly.
  '''
  if isinstance(objs, str):
    return [objs]
  elif not isinstance(objs, list):
    return list(objs)
  else:
    return objs



def add_options_and_position(params, options=None, position=None):
  '''
  Convenience method for adding options and position to parameters.
  '''
  if options:
    params.append(options)
  if position:
    if not isinstance(position, int):
      try:
        position = int(position)
      except ValueError:
        position = -1
    if position >= 0:
      params.append(position)
  return params



################## From python3-aur's ThreadedServers.common ###################

def format_bytes(size):
  """Format bytes for inferior humans."""
  if size < 0x400:
    return '{:d} B'.format(size)
  else:
    size = float(size) / 0x400
  for prefix in ('KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB'):
    if size < 0x400:
      return '{:0.02f} {}'.format(size, prefix)
    else:
      size /= 0x400
  return '{:0.02f} YiB'.format(size)



def format_seconds(s):
  '''Format seconds for inferior humans.'''
  string = ''
  for base, char in (
    (60, 's'),
    (60, 'm'),
    (24, 'h')
  ):
    s, r = divmod(s, base)
    if s == 0:
      return '{:d}{}{}'.format(r, char, string)
    elif r != 0:
      string = '{:02d}{}{}'.format(r, char, string)
  else:
    return '{:d}d{}'.format(s, string)



############################## Aria2JsonRpc Class ##############################

class Aria2JsonRpc(object):
  # TODO: certificate options, etc.
  def __init__(
    self, ID, uri,
    mode='normal',
    token=None,
    http_user=None, http_passwd=None,
    server_cert=None, client_cert=None, client_cert_password=None,
    ssl_protocol=None
  ):
    '''
    ID: the ID to send to the RPC interface

    uri: the URI of the RPC interface

    mode:
      normal - process requests immediately
      batch - queue requests (run with "process_queue")
      format - return RPC request objects

    token: RPC method-level authorization token (set using `--rpc-secret`)

    http_user, http_password: HTTP Basic authentication credentials (deprecated)

    server_cert: server certificate for HTTPS connections

    client_cert: client certificate for HTTPS connections

    client_cert_password: prompt for client certificate password

    ssl_protocol: SSL protocol from the ssl module
    '''
    self.id = ID
    self.uri = uri
    self.mode = mode
    self.queue = []
    self.handlers = dict()
    self.token = token

    if None not in (http_user, http_passwd):
      self.add_HTTPBasicAuthHandler(http_user, http_passwd)

    if server_cert or client_cert:
      self.add_HTTPSHandler(
        server_cert=server_cert,
        client_cert=client_cert,
        client_cert_password=client_cert_password,
        protocol=ssl_protocol
      )

    self.update_opener()



  def log(self, message):
    '''
    Print log messages to STDOUT. Override this if necessary.
    '''
    print(message)



  def log_info(self, message):
    self.log(message)



  def log_error(self, message):
    self.log('error: ' + message)



  def iter_handlers(self):
    '''
    Iterate over handlers.
    '''
    for name in ('HTTPS', 'HTTPBasicAuth'):
      try:
        yield self.handlers[name]
      except KeyError:
        pass



  def update_opener(self):
    '''
    Build an opener from the current handlers.
    '''
    self.opener = urllib.request.build_opener(*self.iter_handlers())



  def remove_handler(self, name):
    '''
    Remove a handler.
    '''
    try:
      del self.handlers[name]
    except KeyError:
      pass



  def add_HTTPBasicAuthHandler(self, user, passwd):
    '''
    Add a handler for HTTP Basic authentication.

    If either user or passwd are None, the handler is removed.
    '''
    handler = urllib.request.HTTPBasicAuthHandler()
    handler.add_password(
      realm='aria2',
      uri=self.uri,
      user=user,
      passwd=passwd,
    )
    self.handlers['HTTPBasicAuth'] = handler



  def remove_HTTPBasicAuthHandler(self):
    self.remove_handler('HTTPBasicAuth')



  def add_HTTPSHandler(
    self,
    server_cert=None,
    client_cert=None,
    client_cert_password=None,
    protocol=None,
  ):
    '''
    Add a handler for HTTPS connections with optional server and client
    certificates.
    '''
    if not protocol:
      protocol = ssl.PROTOCOL_TLSv1
#       protocol = ssl.PROTOCOL_TLSv1_1 # openssl 1.0.1+
#       protocol = ssl.PROTOCOL_TLSv1_2 # Python 3.4+
    context = ssl.SSLContext(protocol)

    if server_cert:
      context.verify_mode = ssl.CERT_REQUIRED
      context.load_verify_locations(cafile=server_cert)
    else:
      context.verify_mode = ssl.CERT_OPTIONAL

    if client_cert:
      context.load_cert_chain(client_cert, password=client_cert_password)

    self.handlers['HTTPS'] = urllib.request.HTTPSHandler(
      context=context,
      check_hostname=False
    )



  def remove_HTTPSHandler(self):
    self.remove_handler('HTTPS')



  def send_request(self, req_obj):
    '''
    Send the request and return the response.
    '''
    req = json.dumps(req_obj).encode('UTF-8')
    try:
      with self.opener.open(self.uri, req) as f:
        obj = json.loads(f.read().decode())
        try:
          return obj['result']
        except KeyError:
          self.log_error('unexpected result: {}'.format(obj))
          return None
    except urllib.error.URLError as e:
      self.log_error(str(e))
      return None
    except http.client.BadStatusLine as e:
      self.log_error('BadStatusLine: {} (HTTPS error?)'.format(e))
      return None



  def jsonrpc(self, method, params=None, prefix='aria2.'):
    '''
    POST a request to the RPC interface.
    '''
    if not params:
      params = []

    if self.token is not None:
      params.insert(0, 'token:{}'.format(self.token))

    req_obj = {
      'jsonrpc' : '2.0',
      'id' : self.id,
      'method' : prefix + method,
      'params' : params,
    }
    if self.mode == 'batch':
      self.queue.append(req_obj)
      return None
    elif self.mode == 'format':
      return req_obj
    else:
      return self.send_request(req_obj)



  def process_queue(self):
    '''
    Processed queued requests.
    '''
    req_obj = self.queue
    self.queue = []
    return self.send_request(req_obj)



############################### Standard Methods ###############################

  def addUri(self, uris, options=None, position=None):
    '''
    aria2.addUri method

    uris: list of URIs

    options: dictionary of additional options

    position: position in queue
    '''
    params = [uris]
    params = add_options_and_position(params, options, position)
    return self.jsonrpc('addUri', params)



  def addTorrent(self, torrent, uris=None, options=None, position=None):
    '''
    aria2.addTorrent method

    torrent: base64-encoded torrent file

    uris: list of webseed URIs

    options: dictionary of additional options

    position: position in queue
    '''
    params = [torrent]
    if uris:
      params.append(uris)
    params = add_options_and_position(params, options, position)
    return self.jsonrpc('addTorrent', params)



  def addMetalink(self, metalink, options=None, position=None):
    '''
    aria2.addMetalink method

    metalink: base64-encoded torrent file

    options: dictionary of additional options

    position: position in queue
    '''
    params = [metalink]
    params = add_options_and_position(params, options, position)
    return self.jsonrpc('addTorrent', params)



  def remove(self, gid):
    '''
    aria2.remove method

    gid: GID to remove
    '''
    params = [gid]
    return self.jsonrpc('remove', params)



  def forceRemove(self, gid):
    '''
    aria2.forceRemove method

    gid: GID to remove
    '''
    params = [gid]
    return self.jsonrpc('forceRemove', params)



  def pause(self, gid):
    '''
    aria2.pause method

    gid: GID to pause
    '''
    params = [gid]
    return self.jsonrpc('pause', params)



  def pauseAll(self):
    '''
    aria2.pauseAll method
    '''
    return self.jsonrpc('pauseAll')



  def forcePause(self, gid):
    '''
    aria2.forcePause method

    gid: GID to pause
    '''
    params = [gid]
    return self.jsonrpc('forcePause', params)



  def forcePauseAll(self):
    '''
    aria2.forcePauseAll method
    '''
    return self.jsonrpc('forcePauseAll')



  def unpause(self, gid):
    '''
    aria2.unpause method

    gid: GID to unpause
    '''
    params = [gid]
    return self.jsonrpc('unpause', params)



  def unpauseAll(self):
    '''
    aria2.unpauseAll method
    '''
    return self.jsonrpc('unpauseAll')



  def tellStatus(self, gid, keys=None):
    '''
    aria2.tellStatus method

    gid: GID to query

    keys: subset of status keys to return (all keys are returned otherwise)

    Returns a dictionary.
    '''
    params = [gid]
    if keys:
      params.append(keys)
    return self.jsonrpc('tellStatus', params)



  def getUris(self, gid):
    '''
    aria2.getUris method

    gid: GID to query

    Returns a list of dictionaries.
    '''
    params = [gid]
    return self.jsonrpc('getUris', params)



  def getFiles(self, gid):
    '''
    aria2.getFiles method

    gid: GID to query

    Returns a list of dictionaries.
    '''
    params = [gid]
    return self.jsonrpc('getFiles', params)



  def getPeers(self, gid):
    '''
    aria2.getPeers method

    gid: GID to query

    Returns a list of dictionaries.
    '''
    params = [gid]
    return self.jsonrpc('getPeers', params)



  def getServers(self, gid):
    '''
    aria2.getServers method

    gid: GID to query

    Returns a list of dictionaries.
    '''
    params = [gid]
    return self.jsonrpc('getServers', params)



  def tellActive(self, keys=None):
    '''
    aria2.tellActive method

    keys: same as tellStatus

    Returns a list of dictionaries. The dictionaries are the same as those
    returned by tellStatus.
    '''
    if keys:
      params = [keys]
    else:
      params = None
    return self.jsonrpc('tellActive', params)



  def tellWaiting(self, offset, num, keys=None):
    '''
    aria2.tellWaiting method

    offset: offset from start of waiting download queue
            (negative values are counted from the end of the queue)

    num: number of downloads to return

    keys: same as tellStatus

    Returns a list of dictionaries. The dictionaries are the same as those
    returned by tellStatus.
    '''
    params = [offset, num]
    if keys:
      params.append(keys)
    return self.jsonrpc('tellWaiting', params)



  def tellStopped(self, offset, num, keys=None):
    '''
    aria2.tellStopped method

    offset: offset from oldest download (same semantics as tellWaiting)

    num: same as tellWaiting

    keys: same as tellStatus

    Returns a list of dictionaries. The dictionaries are the same as those
    returned by tellStatus.
    '''
    params = [offset, num]
    if keys:
      params.append(keys)
    return self.jsonrpc('tellStopped', params)



  def changePosition(self, gid, pos, how):
    '''
    aria2.changePosition method

    gid: GID to change

    pos: the position

    how: "POS_SET", "POS_CUR" or "POS_END"
    '''
    params = [gid, pos, how]
    return self.jsonrpc('changePosition', params)



  def changeUri(self, gid, fileIndex, delUris, addUris, position=None):
    '''
    aria2.changePosition method

    gid: GID to change

    fileIndex: file to affect (1-based)

    delUris: URIs to remove

    addUris: URIs to add

    position: where URIs are inserted, after URIs have been removed
    '''
    params = [gid, fileIndex, delUris, addUris]
    if position:
      params.append(position)
    return self.jsonrpc('changePosition', params)



  def getOption(self, gid):
    '''
    aria2.getOption method

    gid: GID to query

    Returns a dictionary of options.
    '''
    params = [gid]
    return self.jsonrpc('getOption', params)



  def changeOption(self, gid, options):
    '''
    aria2.changeOption method

    gid: GID to change

    options: dictionary of new options
             (not all options can be changed for active downloads)
    '''
    params = [gid, options]
    return self.jsonrpc('changeOption', params)



  def getGlobalOption(self):
    '''
    aria2.getGlobalOption method

    Returns a dictionary.
    '''
    return self.jsonrpc('getGlobalOption')



  def changeGlobalOption(self, options):
    '''
    aria2.changeGlobalOption method

    options: dictionary of new options
    '''
    params = [options]
    return self.jsonrpc('changeGlobalOption', params)



  def getGlobalStat(self):
    '''
    aria2.getGlobalStat method

    Returns a dictionary.
    '''
    return self.jsonrpc('getGlobalStat')



  def purgeDownloadResult(self):
    '''
    aria2.purgeDownloadResult method
    '''
    self.jsonrpc('purgeDownloadResult')



  def removeDownloadResult(self, gid):
    '''
    aria2.removeDownloadResult method

    gid: GID to remove
    '''
    params = [gid]
    return self.jsonrpc('removeDownloadResult', params)



  def getVersion(self):
    '''
    aria2.getVersion method

    Returns a dictionary.
    '''
    return self.jsonrpc('getVersion')



  def getSessionInfo(self):
    '''
    aria2.getSessionInfo method

    Returns a dictionary.
    '''
    return self.jsonrpc('getSessionInfo')



  def shutdown(self):
    '''
    aria2.shutdown method
    '''
    return self.jsonrpc('shutdown')



  def forceShutdown(self):
    '''
    aria2.forceShutdown method
    '''
    return self.jsonrpc('forceShutdown')



  def multicall(self, methods):
    '''
    aria2.multicall method

    methods: list of dictionaries (keys: methodName, params)

    The method names must be those used by Aria2c, e.g. "aria2.tellStatus".
    '''
    params = [methods]
    return self.jsonrpc('multicall', params, prefix='system.')




############################# Convenience Methods ##############################

  def add_torrent(self, path, uris=None, options=None, position=None):
    '''
    A wrapper around addTorrent for loading files.
    '''
    with open(path, 'r') as f:
      torrent = base64.encode(f.read())
    return self.addTorrent(torrent, uris, options, position)



  def add_metalink(self, path, uris=None, options=None, position=None):
    '''
    A wrapper around addMetalink for loading files.
    '''
    with open(path, 'r') as f:
      metalink = base64.encode(f.read())
    return self.addMetalink(metalink, uris, options, position)



  def get_status(self, gids):
    '''
    Get the status of multiple GIDs.
    '''
    methods = [
      {
        'methodName' : 'aria2.tellStatus',
        'params' : [gid, ['gid', 'status']]
      }
      for gid in gids
    ]
    stati = dict()
    response = self.multicall(methods)
    if response:
      for result in response['result']:
        result = result[0]
        gid = result['gid']
        status = result['status']
        stati[gid] = status
    return stati


  def print_status(self):
    status = self.getGlobalStat()
    if status:
      numWaiting = int(status['numWaiting'])
      numStopped = int(status['numStopped'])
      keys = ['totalLength', 'completedLength']
      total = self.tellActive(keys)
      waiting = self.tellWaiting(0, numWaiting, keys)
      if waiting:
        total += waiting
      stopped = self.tellStopped(0, numStopped, keys)
      if stopped:
        total += stopped

      downloadSpeed = int(status['downloadSpeed'])
      uploadSpeed = int(status['uploadSpeed'])
      totalLength = sum(int(x['totalLength']) for x in total)
      completedLength = sum(int(x['completedLength']) for x in total)
      remaining = totalLength - completedLength

      status['downloadSpeed'] = format_bytes(downloadSpeed) + '/s'
      status['uploadSpeed'] = format_bytes(uploadSpeed) + '/s'

      preordered = ('downloadSpeed', 'uploadSpeed')

      rows = list()
      for k in sorted(status):
        if k in preordered:
          continue
        rows.append((k, status[k]))

      rows.extend((x, status[x]) for x in preordered)

      if totalLength > 0:
        rows.append(('total', format(format_bytes(totalLength))))
        rows.append(('completed', format(format_bytes(completedLength))))
        rows.append(('remaining', format(format_bytes(remaining))))
        if completedLength == totalLength:
          eta = 'finished'
        else:
          try:
            eta = format_seconds(remaining // downloadSpeed)
          except ZeroDivisionError:
            eta = 'never'
        rows.append(('ETA', eta))

      l = max(len(r[0]) for r in rows)
      r = max(len(r[1]) for r in rows)
      r = max(r, len(self.uri) - (l + 2))
      fmt = '{:<' + str(l) + 's}  {:>' + str(r) + 's}'

      print(self.uri)
      for k, v in rows:
        print(fmt.format(k, v))



  def queue_uris(self, uris, options, interval=None):
    gid = self.addUri(uris, options)
    print("GID:", gid)

    if gid and interval is not None:
      blanker = ''
      while True:
        response = self.tellStatus(gid, ['status'])
        if response:
          try:
            status = response['status']
          except KeyError:
            print("error: no status returned from server")
          print("{}\rstatus: {}".format(blanker, status), end='')
          blanker = ' ' * len(status)
          if status == 'active':
            time.sleep(interval)
          else:
            break
        else:
          print("error: no response from server")
          break



################################### argparse ###################################

def add_server_arguments(parser):
  """
  Common command-line arguments for the server.

  Accepts an argparse ArgumentParser or group.
  """
  parser.add_argument(
    '-a', '--address', default='localhost',
    help='The server host. Default: %(default)s.'
  )
  parser.add_argument(
    '-p', '--port', type=int, default=DEFAULT_PORT,
    help='The server port. Default: %(default)s.'
  )
  parser.add_argument(
    '-s', '--scheme', default='http',
    help='The server scheme. Default: %(default)s.'
  )

#   parser.add_argument(
#     '--auth', nargs=2,
#     help='HTTP Basic authentication user and password.'
#   )

  parser.add_argument(
    '--token',
    help='Secret RPC token.'
  )

  parser.add_argument(
    '--server-cert',
    help='HTTPS server certificate file, in PEM format.'
  )
  parser.add_argument(
    '--client-cert',
    help='HTTPS client certificate file, in PEM format.'
  )
  parser.add_argument(
    '--client-cert-password',
    help='Prompt for a client certificate password.'
  )


def a2jr_from_args(identity, args):
  """
  Return a new Aria2JsonRpc object using the provided arguments.

  See `add_server_arguments`.
  """
  uri = SERVER_URI_FORMAT.format(args.scheme, args.address, args.port)

#   if args.auth:
#     http_user, http_passwd = args.auth
#   else:
#     http_user = None
#     http_passwd = None

  token = args.token

  if args.client_cert and args.client_cert_password:
    client_cert_password = getpass.getpass('password for {}: '.format(args.client_cert))
  else:
    client_cert_password = None

  return Aria2JsonRpc(
    identity, uri,
    token=token,
#     http_user=http_user, http_passwd=http_passwd,
    server_cert=args.server_cert,
    client_cert=args.client_cert,
    client_cert_password=client_cert_password,
  )