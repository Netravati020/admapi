from typing import Union, Optional

from pydantic import BaseModel
from datetime import datetime

from sqlalchemy import Float


class Admission(BaseModel):
    branch: str
    date: datetime
    Days:str
    plan: str
    oldplan: str

    class Config:
        orm_mode = True

class Patient_data(BaseModel):
    ipno: str
    umr: str
    pname: str
    adate: datetime
    time: datetime
    isbilldone: str
    mobile: int
    alt_mobile: int
    branch:  str
    admntype:  str
    department: str
    wardname: str
    deptcode: str
    organization: str
    admpurpose: str
    last_login:datetime
    discharge_datetime: datetime
    referralpercentage: str
    referral_cal_on: datetime
    accnumber: str
    ifsccode: str
    pancard: str
    referralcreatedon: datetime
    mh_approved_on: datetime
    chapproval: str
    chapproval_by: int
    ch_approved_on: datetime
    billamount: int
    referralamount: int
    discounts: int
    netbill: int
    phar_consum_billamount:float
    consultantentry: str
    consultantremarks: str
    doctor_dateon: datetime
    UCID: str
    cluster_approved_on: datetime
    referral_type: str
    Marketting_executive: str
    sdms_iobid: int
    orgconsession: int
    labsamount: int
    lastinsert_on: datetime
    last_discharge_on: datetime

    class Config:
        arbitrary_types_allowed = True

class Adm(BaseModel):
    date: str
    branch: str
    plan: str


class User(BaseModel):
    name: str
    email:str
    password:str

class Login(BaseModel):
    username: str
    password:str

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str

    class Config:
        orm_mode = True

class TokenData(BaseModel):
    email:  Optional[str] = None

    class Config:
        orm_mode = True