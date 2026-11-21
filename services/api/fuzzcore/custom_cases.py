"""Versioned declarative checks, including one named stateless lab POST."""
import hashlib
import json
import re
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class CustomCase(BaseModel):
    model_config=ConfigDict(extra='forbid')
    path:Literal['/health','/api/status','/custom-fixture','/custom-disposable']
    method:Literal['GET','POST']='GET'
    params:dict[str,str]=Field(default_factory=dict,max_length=1)
    expect_status:Literal[200,404]=200
    contains:str=Field(default='',max_length=64)
    body:dict[str,str]|None=Field(default=None,max_length=1)
    expect_headers:dict[Literal['content-type','x-fixture-mode'],str]=Field(default_factory=dict,max_length=2)

    @field_validator('params')
    @classmethod
    def bounded_markers(cls,value):
        if any(key!='q' or not re.fullmatch(r'[A-Za-z0-9 _-]{0,64}',marker) for key,marker in value.items()):
            raise ValueError('Only one harmless q marker is supported')
        return value

    @field_validator('expect_headers')
    @classmethod
    def header_literals(cls,value):
        if any(not re.fullmatch(r'[\x20-\x7e]{1,64}',literal) for literal in value.values()):
            raise ValueError('Expected header values must be short printable literal text')
        return value

    @model_validator(mode='after')
    def disposable_post_only(self):
        if self.method=='POST':
            if self.path!='/custom-disposable' or self.params or not self.body or set(self.body)!={'marker'} or not re.fullmatch(r'[A-Za-z0-9 _-]{1,64}',self.body['marker']):
                raise ValueError('POST is only a harmless marker to the named stateless disposable fixture')
        elif self.body is not None or self.path=='/custom-disposable':
            raise ValueError('GET cannot carry a body or use the POST-only fixture')
        return self


def canonical(cases):
    normalized=[]
    for case in cases:
        value=CustomCase.model_validate(case).model_dump()
        # Preserve the exact previously stored GET canonical representation/hash.
        if value['body'] is None:value.pop('body')
        if not value['expect_headers']:value.pop('expect_headers')
        normalized.append(value)
    return json.dumps(normalized,sort_keys=True,separators=(',',':'))


def version(cases):
    return hashlib.sha256(canonical(cases).encode()).hexdigest()


def http_custom_probe(client):
    def probe(value):
        case=CustomCase.model_validate(value)
        options={'params':case.params} if case.method=='GET' else {'json':case.body}
        with client.stream(case.method,case.path,headers={'Accept-Encoding':'identity'},**options) as response:
            body=bytearray()
            for chunk in response.iter_bytes(chunk_size=4096):
                if len(body)+len(chunk)>16384:raise ValueError('Fixture evidence budget exceeded')
                body.extend(chunk)
            matches=case.contains.encode() in body
            header_checks={name:{'expected':expected,'matched':response.headers.get(name)==expected} for name,expected in case.expect_headers.items()}
            headers_matched=all(check['matched'] for check in header_checks.values())
            return {'status_code':response.status_code,'bytes':len(body),
                'body_sha256':hashlib.sha256(body).hexdigest(),
                'expected_status':case.expect_status,'text_matched':matches,
                'header_checks':header_checks,'headers_matched':headers_matched,
                'passed':response.status_code==case.expect_status and matches and headers_matched and not 300<=response.status_code<400}
    return probe
