#!/bin/bash
port="$1"
session="$2"
shift 2
if [[ ! -e $session ]]
then
  touch -- "$session"
fi
aria2c \
  --continue \
  --enable-rpc \
  --input-file="$session" \
  --max-concurrent-downloads=20 \
  --max-connection-per-server=10 \
  --rpc-listen-port="$port" \
  --rpc-max-request-size=1000M \
  --save-session-interval=60 \
  --save-session="$session" \
  --rpc-secret="$port" \
  "$@"
