# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

import base64
from functools import singledispatch

import chardet

@singledispatch
def stringify(arg) -> str:
    return arg

@stringify.register(str)
def _(arg):
    return arg

@stringify.register(bytes)
def _(arg):
    encoding = chardet.detect(arg)['encoding']
    if encoding in ("ascii", "utf-8"):
        return arg.decode()
    else:
        return base64.b64encode(arg).decode("utf-8")

# Convert bytes object to serializble string representation
def bytes_to_base64_str(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

# Decode base64-encoded data
def decode_base64(input_str :str) -> bytes:
    v = input_str.encode('utf-8')
    if len(v) % 4 != 0:
        return input_str
    try:
        decoded_value = base64.b64decode(v)
        return decoded_value
    except Exception as exc:
        return input_str
