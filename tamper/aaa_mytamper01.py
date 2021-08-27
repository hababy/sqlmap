#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import PRIORITY
import re

__priority__ = PRIORITY.LOW


def dependencies():
    pass


def tamper(payload, **kwargs):
    """
    双写指定的关键字

    >>> tamper("2) AND 2621=1604 AND (2724=2724")
    2) AANDND 2621=1604 AANDND (2724=2724
    """
    payload = payload.replace("OR", "OORR").replace("AND", "AANDND")
    return payload if payload else payload
