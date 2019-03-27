#! /bin/sh
# flatc version 1.10.0
# pip install cfbc

flatc --rust protocol_select.fbs
flatc -b --schema protocol_select.fbs
cfbc protocol_select.bfbs
rm *_builder.rs protocol_select.bfbs
