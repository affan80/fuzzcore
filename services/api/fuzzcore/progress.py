"""Persisted request progress, not vulnerability confidence or proof of safety."""
import json

BUDGETS={'directories':4,'vhosts':3,'api':6,'parameters':6,'subdomains':3}
TERMINAL={'completed','cancelled','failed','timed_out','interrupted'}


def initial_progress(modules,custom_cases):
    return {module:{'state':'queued','planned':len(custom_cases) if module=='custom' else BUDGETS[module],
                    'attempted':0,'completed':0} for module in modules}


def progress_for(row):
    value=json.loads(row.module_progress)
    if row.status in TERMINAL:
        for item in value.values():
            if item['state']=='running':item['state']=row.status
            elif item['state']=='queued':item['state']='not_run'
    return value


def settle_progress(row):
    row.module_progress=json.dumps(progress_for(row))


def advance_progress(row,module,*,completed=False):
    value=json.loads(row.module_progress)
    item=value[module]
    if completed:
        item['completed']+=1
        if item['completed']==item['planned']:item['state']='completed'
    else:
        item['state']='running';item['attempted']+=1
    row.module_progress=json.dumps(value)


def fail_module(row,module):
    value=json.loads(row.module_progress)
    value[module]['state']='failed'
    row.module_progress=json.dumps(value)
