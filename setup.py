#!/usr/bin/env python3

from distutils.core import setup
import time

setup(
  name='''Aria2JsonRpc''',
  version=time.strftime('%Y.%m.%d.%H.%M.%S', time.gmtime(1398528950)),
  description='''A wrapper class around Aria2's JSON RPC interface.''',
  author='''Xyne''',
  author_email='''ac xunilhcra enyx, backwards''',
  url='''http://xyne.archlinux.ca/projects/python3-aria2jsonrpc''',
  py_modules=['''Aria2JsonRpc'''],
)
