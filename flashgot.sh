#!/bin/bash

# flashgot command line template(e.g.):
# 6800 [URL] [CFILE] [FOLDER] [FNAME] [...]
# Other arguments are in the form of key pairs like "key=value" for aria2
token="$1"
url="$2"
cookies_file="$3"
directory="$4"
output="$5"
if [[ "$output" != "" ]];then
    shift 5
else
    shift 4
fi
/usr/bin/a2jrg --token "$token"  "$url" -o dir="$directory"  out="$output" load-cookies="$cookies_file" "$@"
