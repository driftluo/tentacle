#! /bin/sh
# flatc version 1.10.0
# pip install cfbc

flatc --rust protocol.fbs
flatc -b --schema protocol.fbs
cfbc protocol.bfbs
rm *_builder.rs protocol.bfbs
