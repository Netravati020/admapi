import datetime

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Float, Date, BigInteger, table, DateTime
from sqlalchemy.schema import Column
from sqlalchemy.orm import relationship

from database import Base


class Admission(Base):
    __tablename__= 'admissionplan_calendars'

    sno = Column(Integer, primary_key=True, autoincrement=True, index=True)
    branch = Column(String(100), index=True)
    date = Column(Date(), index=True)
    days = Column(String(100), unique=True, index=True)
    plan = Column(Integer, index=True)
    oldplan = Column(Integer, index=True)

    # a_ID = Column(Integer, ForeignKey("admission_dummy.sno"))
    # patie_ID = Column(Integer, ForeignKey("admission_dummy.sno"))

class Patient_data(Base):
    __tablename__='patient_data'

    sno= Column(Integer, primary_key=True, autoincrement=True, index=True)
    ipno= Column(String(100), index=True)
    umr= Column(String(100), index=True)
    pname= Column(String(100), index=True)
    adate= Column(Date(), index=True)
    time=Column(DateTime, index=True)
    isbilldone=Column(String(100), index=True)
    mobile=Column(Integer, index=True)
    alt_mobile= Column(Integer, index=True)
    branch=Column(String(100), index=True)
    admntype=Column(String(100), index=True)
    consultant=Column(String(100), index=True)
    department=Column(String(100), index=True)
    wardname=Column(String(100), index=True)
    deptcode=Column(String(100), index=True)
    organization=Column(String(100), index=True)
    admpurpose=Column(String(100), index=True)
    last_login=Column(DateTime, index=True)
    discharge_datetime=Column(DateTime, index=True)
    referralpercentage=Column(String(100),index=True)
    referral_cal_on=Column(DateTime, index=True)
    accnumber=Column(String(100),index=True)
    ifsccode=Column(String(100), index=True)
    pancard=Column(String(100), index=True)
    referralcreatedon=Column(DateTime, index=True)
    mh_approved_on=Column(DateTime, index=True)
    chapproval=Column(String(100), index=True)
    chapproval_by=Column(Integer, index=True)
    ch_approved_on=Column(DateTime, index=True)
    billamount=Column(Integer, index=True)
    referralamount=Column(Integer, index=True)
    discounts=Column(Integer, index=True)
    netbill=Column(Integer, index=True)
    phar_consum_billamount=Column(Float, index=True)
    consultantentry=Column(String(100), index=True)
    consultantremarks=Column(String(100), index=True)
    doctor_dateon=Column(DateTime, index=True)
    UCID= Column(String(100), index=True)
    cluster_approved_on=Column(DateTime, index=True)
    referral_type=Column(String(100), index=True)
    Marketting_executive=Column(String(100), index=True)
    sdms_iobid=Column(Integer, index=True)
    orgconsession=Column(Integer, index=True)
    labsamount=Column(Integer, index=True)
    lastinsert_on=Column(DateTime, index=True)
    last_discharge_on=Column(DateTime, index=True)

    # patient = relationship("Item", back_populates="owner")
    #
    # branch_id = Column(Integer, ForeignKey("admission_dummy_table.sno"))

class admission_dummy(Base):
    __tablename__= 'admission_dummy_table'

    sno = Column(Integer, primary_key=True, autoincrement=True, index=True)
    branch = Column(String(100), index=True)
    plan = Column(Integer, index=True)
    adm = Column(String(100), index=True)
    ach = Column(String(100), index=True)
    gap = Column(String(100), index=True)
    mtc = Column(String(100), index=True)
    clustername = Column(String(100), index=True)
    cname = Column(String(100), index=True)
    status = Column(String(100), index=True)

    # adm_ID = Column(Integer, ForeignKey("Admission.sno"))
    # patient_ID = Column(Integer, ForeignKey("Patient_data.sno"))
    # owner = relationship("User", back_populates="patient")


class User(Base):
    __tablename__ = "usersdetails"

    id= Column(Integer, primary_key=True,index=True, autoincrement=True)
    name = Column(String(50), index=True)
    email = Column(String(100), unique=True)
    password = Column(String(100), index=True)



