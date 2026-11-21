"""Authenticated report rendering. Every target/user string is plain escaped text."""
from collections import Counter
import html
import json
from sqlalchemy import select
from .core import Finding,utcnow

LIMITATIONS='An empty result is not a security certificate. Fixed synthetic lab only; no third-party ownership validation, exhaustive assessment, automatic fix or production security claim. Fixture-confirmed evidence applies only to known synthetic controls. A fixed review is a manual decision supported by a completed matched-scope retest where that fingerprint was not observed; it is not a security certificate or proof of an applied source change. Native Android and trusted HTTPS acceptance remain separate.'


def finding_json(row):
    return {key:getattr(row,key) for key in ('id','path','status_code','summary','module','severity','confidence','review_state','review_note','review_retest_id','reviewed_at')} | {'evidence':json.loads(row.evidence)}


def report(db,row,serialize,filters=None):
    findings=[finding_json(item) for item in db.scalars(select(Finding).where(Finding.scan_id==row.id).order_by(Finding.id).limit(100))]
    from .report_filters import matching
    filters=filters or {};unfiltered=len(findings);findings=matching(findings,filters)
    return {'filters':filters,'filtered':bool(filters),'unfiltered_findings':unfiltered,'schema_version':'report-v1','generated_at':utcnow(),'scan':serialize(row),
        'partial':row.status!='completed',
        'summary':f"{len(findings)} recorded findings or observations. Review the scope and evidence before drawing conclusions.",
        'totals':{'findings':len(findings),'severity':dict(Counter(f['severity'] for f in findings)),
                  'confidence':dict(Counter(f['confidence'] for f in findings)),
                  'module':dict(Counter(f['module'] for f in findings)),
                  'review_state':dict(Counter(f['review_state'] for f in findings))},
        'findings':findings,'limitations':LIMITATIONS}


def render_html(value):
    escape=lambda text:html.escape(str(text),quote=True)
    findings=''.join('<article><h2>'+escape(f['path'])+'</h2><p>'+escape(f['module'])+' / '+escape(f['severity'])+' / '+escape(f['confidence'])+' / '+escape(f['review_state'])+'</p><p>'+escape(f['summary'])+'</p><pre>'+escape(json.dumps(f['evidence'],indent=2))+'</pre><p>Review note: '+escape(f['review_note'])+'</p><p>Manual review time: '+escape(f.get('reviewed_at') or 'not reviewed')+'</p><p>Supporting linked retest: '+escape(f.get('review_retest_id') or 'none')+'</p></article>' for f in value['findings'])
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>FuzzCore lab report</title><style>body{font:16px/1.6 system-ui,sans-serif;max-width:900px;margin:40px auto;padding:0 20px;color:#172635}h1{font-size:30px}h2{overflow-wrap:anywhere}article{border-top:1px solid #ccd7df;padding:20px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f0f4f7;padding:16px;font-size:12px}.notice{border-left:4px solid #156c58;padding:15px;background:#edf7f3}@media print{body{margin:0;max-width:none}article{break-inside:avoid}}</style></head><body><h1>FuzzCore lab report</h1><p>'+escape(value['summary'])+'</p><h2>Report filters</h2><pre>'+escape(json.dumps(value.get('filters',{}),indent=2))+'</pre><p>'+escape(str(value.get('unfiltered_findings',value['totals']['findings'])))+' total unfiltered findings or observations.</p><div class="notice">'+escape(value['limitations'])+'</div><h2>Scope and status</h2><pre>'+escape(json.dumps(value['scan'],indent=2))+'</pre><p>Partial: '+escape(value['partial'])+'</p><h2>Totals</h2><pre>'+escape(json.dumps(value['totals'],indent=2))+'</pre>'+findings+'</body></html>'
