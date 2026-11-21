"""Immutable owner-scoped declarative case versions. Saving never queues a scan."""
import json
import uuid
from fastapi import Depends,HTTPException,Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel,ConfigDict,Field,field_validator
from sqlalchemy import select,and_,or_
from sqlalchemy.exc import IntegrityError
from .core import SavedCaseVersion
from .custom_cases import CustomCase,canonical,version


class NewCaseVersion(BaseModel):
    model_config=ConfigDict(extra='forbid')
    name:str=Field(min_length=1,max_length=80)
    cases:list[CustomCase]=Field(min_length=1,max_length=3)

    @field_validator('name')
    @classmethod
    def plain_label(cls,value):
        if not value.strip() or any(ord(c)<32 or ord(c)==127 for c in value):raise ValueError('Use a short plain-text name')
        return value.strip()


def serialize_case(row):
    return {'id':row.id,'name':row.name,'version':row.case_version,'schema_version':'declarative-v2','cases':json.loads(row.cases),'created_at':row.created_at}


def attach_saved_cases(app,sessions,auth):
    @app.post('/v1/custom-cases',status_code=201)
    def save_case(body:NewCaseVersion,owner=Depends(auth)):
        cases=[c.model_dump() for c in body.cases];digest=version(cases);content=canonical(cases)
        # Unique owner/slot and a DB check enforce the 100-version cap even
        # across concurrent API processes. Duplicate saves return the first ID.
        for _ in range(100):
            with sessions() as db:
                old=db.scalar(select(SavedCaseVersion).where(SavedCaseVersion.owner==owner,SavedCaseVersion.name==body.name,SavedCaseVersion.case_version==digest))
                if old:return JSONResponse(serialize_case(old),status_code=200)
                used=set(db.scalars(select(SavedCaseVersion.slot).where(SavedCaseVersion.owner==owner)))
                if len(used)>=100:raise HTTPException(409,'saved_case_limit_reached')
                slot=next(i for i in range(100) if i not in used)
                row=SavedCaseVersion(id=str(uuid.uuid4()),owner=owner,name=body.name,case_version=digest,cases=content,slot=slot)
                db.add(row)
                try:db.commit()
                except IntegrityError:db.rollback();continue
                return serialize_case(row)
        raise HTTPException(409,'saved_case_conflict_retry')

    @app.get('/v1/custom-cases')
    def list_cases(after_id:str|None=Query(default=None,min_length=1,max_length=64),owner=Depends(auth)):
        with sessions() as db:
            query=select(SavedCaseVersion).where(SavedCaseVersion.owner==owner)
            if after_id:
                cursor=db.get(SavedCaseVersion,after_id)
                if not cursor or cursor.owner!=owner:raise HTTPException(404,'saved_case_not_found')
                query=query.where(or_(SavedCaseVersion.created_at<cursor.created_at,and_(SavedCaseVersion.created_at==cursor.created_at,SavedCaseVersion.id<cursor.id)))
            return [serialize_case(row) for row in db.scalars(query.order_by(SavedCaseVersion.created_at.desc(),SavedCaseVersion.id.desc()).limit(50))]

    @app.get('/v1/custom-cases/{case_id}')
    def get_case(case_id:str,owner=Depends(auth)):
        with sessions() as db:
            row=db.get(SavedCaseVersion,case_id)
            if not row or row.owner!=owner:raise HTTPException(404,'saved_case_not_found')
            return serialize_case(row)
