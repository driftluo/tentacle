#! /bin/sh
# flatc version 1.10.0
# pip install cfbc

flatc --rust handshake.fbs
flatc -b --schema handshake.fbs
cfbc handshake.bfbs
rm *_builder.rs handshake.bfbs
