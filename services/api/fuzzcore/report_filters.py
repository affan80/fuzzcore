from typing import Literal


def report_filters(
    severity:Literal['high','medium','low','informational']|None=None,
    module:Literal['directories','vhosts','api','parameters','custom','subdomains']|None=None,
    confidence:Literal['fixture-confirmed','observed','signal']|None=None,
    review_state:Literal['open','acknowledged','retest_requested','fixed']|None=None):
    return {key:value for key,value in {'severity':severity,'module':module,'confidence':confidence,'review_state':review_state}.items() if value is not None}


def matching(findings,filters):
    return [f for f in findings if all(f[key]==value for key,value in filters.items())]


def fingerprint(item):
    import json
    return (item.module,item.path,json.loads(item.evidence).get('rule_id','resource-status-v1'))
