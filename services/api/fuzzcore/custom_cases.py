"""Versioned declarative checks. No code, arbitrary URLs, templates or writes."""
import hashlib
import json
import re
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator


class CustomCase(BaseModel):
    model_config=ConfigDict(extra='forbid')
    path:Literal['/health','/api/status','/custom-fixture']
    method:Literal['GET']='GET'
    params:dict[str,str]=Field(default_factory=dict,max_length=1)
    expect_status:Literal[200,404]=200
    contains:str=Field(default='',max_length=64)

    @field_validator('params')
    @classmethod
    def bounded_markers(cls,value):
        if any(key!='q' or not re.fullmatch(r'[A-Za-z0-9 _-]{0,64}',marker) for key,marker in value.items()):
            raise ValueError('Only one harmless q marker is supported')
        return value


def canonical(cases):
    return json.dumps([CustomCase.model_validate(case).model_dump() for case in cases],sort_keys=True,separators=(',',':'))


def version(cases):
    return hashlib.sha256(canonical(cases).encode()).hexdigest()


def http_custom_probe(client):
    def probe(value):
        case=CustomCase.model_validate(value)
        with client.stream('GET',case.path,params=case.params,headers={'Accept-Encoding':'identity'}) as response:
            body=bytearray()
            for chunk in response.iter_bytes(chunk_size=4096):
                if len(body)+len(chunk)>16384:raise ValueError('Fixture evidence budget exceeded')
                body.extend(chunk)
            matches=case.contains.encode() in body
            return {'status_code':response.status_code,'bytes':len(body),
                'body_sha256':hashlib.sha256(body).hexdigest(),
                'expected_status':case.expect_status,'text_matched':matches,
                'passed':response.status_code==case.expect_status and matches and not 300<=response.status_code<400}
    return probe
