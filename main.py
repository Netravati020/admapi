import parser

from fastapi import FastAPI, Depends, status, HTTPException, Query
import tokn
import oauth
import hashing
from database import engine, SessionLocal, conn
from sqlalchemy.orm import Session

import schema
import models
from models import *
from sqlalchemy import and_, or_, not_
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
from datetime import  datetime

app=FastAPI()

from fastapi.security import HTTPBasic, HTTPBasicCredentials
security = HTTPBasic()
import string
import secrets

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
models.Base.metadata.create_all(bind=engine)

pwd_cxt = CryptContext(schemes=["bcrypt"], deprecated="auto")



# @app.post('/user', tags=['Userlogin'])
# def create_user(request: schema.User, db:Session=Depends(get_db)):
#
#     new_user= models.User(name=request.name, email=request.email, password=hashing.Hash.bcrypt(request.password))
#
#     db.add(new_user)
#     db.commit()
#     db.refresh(new_user)
#     return new_user


# user authentication
# @app.post("/token", tags=['Authentication'])
# async def login_access(request:OAuth2PasswordRequestForm = Depends(),db:Session=Depends(get_db)):
#     user = db.query(models.User).filter(models.User.email == request.username).first()
#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_404_NOT_FOUND,
#             detail="Incorrect username or password")
#
#     if not hashing.Hash.verify(user.password, request.password):
#         raise HTTPException(
#             status_code=status.HTTP_404_NOT_FOUND,
#             detail="Incorrect  password")
#
#     access_token = tokn.create_access_token(data={"sub": user.email})
#     return {"access_token": access_token, "token_type": "bearer"}
def get_current_username(credentials: HTTPBasicCredentials = Depends(security)):
    current_username_bytes = credentials.username.encode("utf8")
    correct_username_bytes = b"netravati"
    is_correct_username = secrets.compare_digest(
        current_username_bytes, correct_username_bytes
    )
    current_password_bytes = credentials.password.encode("utf8")
    correct_password_bytes = b"netra"
    is_correct_password = secrets.compare_digest(
        current_password_bytes, correct_password_bytes
    )
    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username



from dateutil import parser
from datetime import datetime

@app.get('/All', tags=['admission api'])
def read_all(date_one:str, mtd_date:str, db: Session=Depends(get_db), credentials: HTTPBasicCredentials = Depends(security)):
    # formats= '%d, %b %Y'
    # for format in formats:
    #     try:

    x= datetime.strftime(parser.parse(date_one),'%d, %b %Y')
    print(x,type(x))
    da=datetime.strptime(x,'%d, %b %Y').date()
    print(da,type(da))
    # new= datetime.strftime(parser.parse(date_one),format)
    # print(new,type(new))

    y = datetime.strftime(parser.parse(mtd_date),'%d, %b %Y')
    mtd_dat= datetime.strptime(y,'%d, %b %Y').date()
    print(mtd_dat)
    u_user_m=da.month
    v_user_y=da.year
    print(u_user_m,v_user_y)
    print(mtd_dat.month)

    date_str= '2022-08-01'
    f = datetime.strftime(parser.parse(date_str),'%d, %b %Y')
    fa = datetime.strptime(f, '%d, %b %Y').date()
    c_month= fa.month
    print(c_month,type(c_month))
    c_year= fa.year
    print(c_year, type(c_year))



    if(u_user_m<c_month):
        adm_san = db.query(models.Patient_data.adate,
                           models.Patient_data.branch,
                           models.Patient_data.ipno,
                           models.Patient_data.organization,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.consultant,
                           models.Patient_data.isbilldone)\
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Sangareddy',
                   models.Patient_data.organization != "Medicover Associate",
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'GENERAL SURGERY',
                   models.Patient_data.consultant != 'K.SRIDHAR',
                   models.Patient_data.wardname != 'DIALYSIS WARD',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled').count()
        plan_san = 60

        mtd_san = db.query(models.Patient_data.adate,
                           models.Patient_data.branch,
                           models.Patient_data.ipno,
                           models.Patient_data.organization,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.consultant,
                           models.Patient_data.isbilldone)\
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Sangareddy',
                   models.Patient_data.organization != "Medicover Associate",
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'GENERAL SURGERY',
                   models.Patient_data.consultant != 'K.SRIDHAR',
                   models.Patient_data.wardname != 'DIALYSIS WARD',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled').count()
        try:
            Ach_p_san = round((adm_san / plan_san) * 100, 2)
        except ZeroDivisionError:
            Ach_p_san=0

        gap_san = adm_san - plan_san
        cluster_san = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(models.admission_dummy.branch == 'Sangareddy').first()
        clustername_san = cluster_san[0]
        cname_san = cluster_san[1]
        status_san = cluster_san[2]

        # query for Kurnool branch
        adm_k = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.consultant,
                         models.Patient_data.department,
                         models.Patient_data.wardname,
                         models.Patient_data.branch,
                         models.Patient_data.adate) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Kurnool',
                   models.Patient_data.organization != "Medicover Associate",
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DAY CARE',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_k = 60

        mtd_k = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.consultant,
                         models.Patient_data.department,
                         models.Patient_data.wardname,
                         models.Patient_data.branch,
                         models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Kurnool',
                   models.Patient_data.organization != "Medicover Associate",
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
                   models.Patient_data.wardname != 'DAY CARE',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        try:
            Ach_p_k = round((adm_k / plan_k) * 100, 2)
        except ZeroDivisionError:
            Ach_p_k=0


        # print(adm_k)
        # Ach_p_k = round((adm_k / plan_k) * 100, 2)
        gap_k = adm_k - plan_k
        cluster_k = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(models.admission_dummy.branch == 'kurnool').first()
        clustername_k = cluster_k[0]
        cname_k = cluster_k[1]
        status_k = cluster_k[2]

        # query for Vizag Unit1 branch
        adm_v = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.wardname,
                         models.Patient_data.adate, models.Patient_data.branch)\
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Vizag Unit 1',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'CRADLE WARD').count()

        plan_v = 60

        mtd_v = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.consultant,
                         models.Patient_data.department,
                         models.Patient_data.wardname,
                         models.Patient_data.branch,
                         models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Vizag Unit 1',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.wardname != 'CRADLE WARD',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        try:
            Ach_p_v = round((adm_v / plan_v) * 100, 2)
        except ZeroDivisionError:
            Ach_p_v=0
        gap_v = adm_v - plan_v
        cluster_v = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(models.admission_dummy.branch == 'Vizag Unit 1').first()
        clustername_v = cluster_v[0]
        cname_v = cluster_v[1]
        status_v = cluster_v[2]

        # query for vizag unit 3
        adm_viz3 = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.wardname,
                            models.Patient_data.department,
                            models.Patient_data.adate,
                            models.Patient_data.branch)\
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Vizag Unit 3',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_viz3 = 60
        mtd_viz3 = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.consultant,
                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.branch == 'Vizag Unit 3',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        try:
            Ach_p_viz3 = round((adm_viz3 / plan_viz3) * 100, 2)
        except ZeroDivisionError:
            Ach_p_viz3=0
        gap_viz3 = adm_viz3 - plan_viz3

        cluster_viz3 = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(models.admission_dummy.branch == 'Vizag Unit 3').first()
        clustername_viz3 = cluster_viz3[0]
        cname_viz3 = cluster_viz3[1]
        status_viz3 = cluster_viz3[2]

        # query for Madhapur branch
        adm_m = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.wardname,
                         models.Patient_data.department,
                         models.Patient_data.adate,
                         models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Madhapur',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_m = 60
        mtd_m = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.consultant,
                         models.Patient_data.department,
                         models.Patient_data.wardname,
                         models.Patient_data.branch,
                         models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.branch == 'Madhapur',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        try:
            Ach_p_m = round((adm_m / plan_m) * 100, 2)
        except ZeroDivisionError:
            Ach_p_m=0
        gap_m = adm_m - plan_m

        cluster_m = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(models.admission_dummy.branch == 'Madhapur').first()
        clustername_m = cluster_m[0]
        cname_m = cluster_m[1]
        status_m = cluster_m[2]

        # query for Karimnagar branch
        adm_karim = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.wardname,
                             models.Patient_data.department,
                             models.Patient_data.adate,
                             models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Karimnagar',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_karim = 60
        mtd_karim = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.consultant,
                             models.Patient_data.department,
                             models.Patient_data.wardname,
                             models.Patient_data.branch,
                             models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.branch == 'Karimnagar',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        try:
            Ach_p_karim = round((adm_m / plan_m) * 100, 2)
        except ZeroDivisionError:
            Ach_p_karim=0
        gap_karim = adm_m - plan_m

        cluster_karim = db.query(models.admission_dummy.clustername, models.admission_dummy.cname, models.admission_dummy.status).filter(models.admission_dummy.branch == 'Karimnagar').first()
        clustername_karim = cluster_karim[0]
        cname_karim = cluster_karim[1]
        status_karim = cluster_karim[2]

        # query for Nashik branch
        adm_nash = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.wardname,
                            models.Patient_data.department,
                            models.Patient_data.adate,
                            models.Patient_data.branch) \
            .where(models.Patient_data.adate == date_one,
                   models.Patient_data.branch == 'Nashik',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_nash = 60
        mtd_nash = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.branch == 'Nashik',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        try:
            Ach_p_nash = round((adm_nash / plan_nash) * 100, 2)
        except ZeroDivisionError:
            Ach_p_nash=0
        gap_nash = adm_nash - plan_nash

        cluster_nash = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(models.admission_dummy.branch == 'Nashik').first()
        clustername_nash = cluster_nash[0]
        cname_nash = cluster_nash[1]
        status_nash = cluster_nash[2]

        # query for Nizamabad branch
        adm_niza = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.wardname,
                            models.Patient_data.department,
                            models.Patient_data.adate,
                            models.Patient_data.branch) \
            .where(models.Patient_data.adate == date_one,
                   models.Patient_data.branch == 'Nizamabad',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_niza = 60
        mtd_niza = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Nizamabad',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        try:
            Ach_p_niza = round((adm_niza / plan_niza) * 100, 2)
        except ZeroDivisionError:
            Ach_p_niza=0
        gap_niza = adm_niza - plan_niza

        cluster_niza = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(models.admission_dummy.branch == 'Nellore').first()
        clustername_niza = cluster_niza[0]
        cname_niza = cluster_niza[1]
        status_niza = cluster_niza[2]

        # query for Nellore branch
        adm_nello = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.wardname,
                             models.Patient_data.department,
                             models.Patient_data.adate,
                             models.Patient_data.branch) \
            .where(models.Patient_data.adate == date_one,
                   models.Patient_data.branch == 'Nellore',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_nello = 60
        mtd_nello = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.consultant,
                             models.Patient_data.department,
                             models.Patient_data.wardname,
                             models.Patient_data.branch,
                             models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Nellore',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        try:
            Ach_p_nello = round((adm_nello / plan_nello) * 100, 2)
        except ZeroDivisionError:
            Ach_p_nello=0
        gap_nello = adm_nello - plan_nello

        cluster_nello = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(models.admission_dummy.branch == 'Nellore').first()
        clustername_nello = cluster_nello[0]
        cname_nello = cluster_nello[1]
        status_nello = cluster_nello[2]

        # query for vizag unit 4
        adm_viz_u_4 = db.query(models.Patient_data.admntype,
                               models.Patient_data.ipno,
                               models.Patient_data.isbilldone,
                               models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Vizag Unit 4',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.admntype != 'D').count()

        plan_viz_u_4 = 60
        mtd_viz_u_4 = db.query(models.Patient_data.admntype,
                               models.Patient_data.ipno,
                               models.Patient_data.isbilldone,
                               models.Patient_data.branch,
                               models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Vizag Unit 4',
                   models.Patient_data.admntype != 'D',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        try:
            Ach_p_viz_u_4 = round((adm_viz_u_4 / plan_viz_u_4) * 100, 2)
        except ZeroDivisionError:
            Ach_p_viz_u_4=0
        gap_viz_u_4 = adm_viz_u_4 - plan_viz_u_4
        cluster_viz_u_4 = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(models.admission_dummy.branch == 'Vizag Unit 4').first()
        clustername_viz_u_4 = cluster_viz_u_4[0]
        cname_viz_u_4 = cluster_viz_u_4[1]
        status_viz_u_4 = cluster_viz_u_4[2]

        # query for Aurangabad branch
        adm_aur = db.query(models.Patient_data.admntype,
                           models.Patient_data.ipno,
                           models.Patient_data.isbilldone,
                           models.Patient_data.branch)\
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Aurangabad',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.admntype != 'D').count()

        plan_aur = 60
        mtd_aur = db.query(models.Patient_data.admntype,
                           models.Patient_data.ipno,
                           models.Patient_data.isbilldone,
                           models.Patient_data.branch,
                           models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Aurangabad',

                   models.Patient_data.admntype != 'D',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        try:
            Ach_p_aur = round((adm_aur / plan_aur) * 100, 2)
        except ZeroDivisionError:
            Ach_p_aur=0
        gap_aur = adm_aur - plan_aur
        cluastrer_aur = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(models.admission_dummy.branch == 'Aurangabad').first()
        clustername_aur = cluastrer_aur[0]
        cname_aur = cluastrer_aur[1]
        status_aur = cluastrer_aur[2]

        # query for Sangamner branch
        adm_sang = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.wardname,
                            models.Patient_data.adate,
                            models.Patient_data.branch) \
            .where(models.Patient_data.adate == date_one,
                   models.Patient_data.branch == 'Sangamner',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',

                   models.Patient_data.wardname != 'DIALYSIS WARD').count()

        plan_sang = 60
        mtd_sang = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.consultant,
                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Sangamner',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.wardname != 'DIALYSIS WARD',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        try:
            Ach_p_sang = round((adm_sang / plan_sang) * 100, 2)
        except ZeroDivisionError:
            Ach_p_sang=0
        gap_sang = adm_sang - plan_sang

        cluster_sang = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(models.admission_dummy.branch == 'Sangamner').first()
        clustername_sang = cluster_sang[0]
        cname_sang = cluster_sang[1]
        status_sang = cluster_sang[2]

        # query for Kakinada branch
        adm_kaki = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.wardname,
                            models.Patient_data.department,
                            models.Patient_data.adate,
                            models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Kakinada',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_kaki = 60
        mtd_kaki = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.consultant,
                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Kakinada',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        try:
            Ach_p_kaki = round((adm_kaki / plan_kaki) * 100, 2)
        except ZeroDivisionError:
            Ach_p_kaki=0
        gap_kaki = adm_kaki - plan_kaki

        cluster_kaki = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(models.admission_dummy.branch == 'Kakinada').first()
        clustername_kaki = cluster_kaki[0]
        cname_kaki = cluster_kaki[1]
        status_kaki = cluster_kaki[2]

        # query for Mci branch
        adm_mci = db.query(models.Patient_data.organization,
                           models.Patient_data.ipno,
                           models.Patient_data.isbilldone,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.adate,
                           models.Patient_data.branch)\
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Mci',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.wardname != 'DIALY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.department != 'RADIATION ONCOLOGY').count()

        plan_mci = 60

        mtd_mci = db.query(models.Patient_data.organization,
                           models.Patient_data.ipno,
                           models.Patient_data.isbilldone,
                           models.Patient_data.consultant,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.branch,
                           models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Mci',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.wardname != 'DIALY',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        try:
            Ach_p_mci = round((adm_mci / plan_mci) * 100, 2)
        except ZeroDivisionError:
            Ach_p_mci=0
        gap_mci = adm_mci - plan_mci

        cluster_mci = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(models.admission_dummy.branch == 'Mci').first()
        clustername_mci = cluster_mci[0]
        cname_mci = cluster_mci[1]
        status_mci = cluster_mci[2]

        # query for begumpet
        adm_begam = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.wardname,
                            models.Patient_data.adate,
                            models.Patient_data.branch) \
            .where(models.Patient_data.adate == date_one,
                   models.Patient_data.branch == 'Begumpet',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS WARD').count()
        try:
            ach_p_begam = round((adm_mci / plan_mci) * 100, 2)
        except ZeroDivisionError:
            ach_p_begam=0
        plan_begam = 60
        gap_begam = adm_begam - plan_begam
        mtd_begam = db.query(models.Patient_data.organization,
                           models.Patient_data.ipno,
                           models.Patient_data.isbilldone,
                           models.Patient_data.consultant,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.branch,
                           models.Patient_data.adate)\
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Begumpet',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.wardname != 'DIALY',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        clustername_begam = 'Megha'
        cname_begam = 'ROTA'
        status_begam = 'Active'

        # query for navimumbai
        adm_navim = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.wardname,
                            models.Patient_data.adate,
                            models.Patient_data.branch) \
            .where(models.Patient_data.adate == date_one,
                   models.Patient_data.branch == 'Navi Mumbai',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS WARD').count()
        try:
            ach_p_navim = round((adm_mci / plan_mci) * 100, 2)
        except ZeroDivisionError:
            ach_p_navim=0
        plan_navim = 60
        gap_navim = adm_navim - plan_navim
        mtd_navim = db.query(models.Patient_data.organization,
                           models.Patient_data.ipno,
                           models.Patient_data.isbilldone,
                           models.Patient_data.consultant,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.branch,
                           models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Begumpet',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.wardname != 'DIALY',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()


        clustername_navim = 'Sachin'
        cname_navim = 'Maharastra'
        status_navim = 'Active'

        sangareddy = {"date": date_one, "admission": adm_san, "Achieved_p": Ach_p_san, "gap": gap_san, "plan": plan_san,"mtd": mtd_san, "clustername": clustername_san, "cname": cname_san, "status": status_san}
        kurnool = {"date": date_one, "admission": adm_k, "Achieved_p": Ach_p_k, "gap": gap_k, "plan": plan_k,"mtd": mtd_k, "clustername": clustername_k, "cname": cname_k, "status": status_k}
        viz_unit1 = {"date": date_one, "admission": adm_v, "Achieved_p": Ach_p_v, "gap": gap_v, "plan": plan_v,"mtd": mtd_v, "clustername": clustername_v, "cname": cname_v, "status": status_v}
        viz_unit3 = {"date": date_one, "admission": adm_viz3, "Achieved_p": Ach_p_viz3, "gap": gap_viz3,"plan": plan_viz3, "mtd": mtd_viz3, "clustername": clustername_viz3, "cname": cname_viz3,"status": status_viz3}
        madhapur = {"date": date_one, "admission": adm_m, "Achieved_p": Ach_p_m, "gap": gap_m, "plan": plan_m,"mtd": mtd_m, "clustername": clustername_m, "cname": cname_m, "status": status_m}
        karimnagar = {"date": date_one, "admission": adm_karim, "Achieved_p": Ach_p_karim, "gap": gap_karim, "plan": plan_karim, "mtd": mtd_karim, "clustername": clustername_karim, "cname": cname_karim,"status": status_karim}
        nashik = {"date": date_one, "admission": adm_nash, "Achieved_p": Ach_p_nash, "gap": gap_nash, "plan": plan_nash,"mtd": mtd_nash, "clustername": clustername_nash, "cname": cname_nash, "status": status_nash}
        nizamabad = {"date": date_one, "admission": adm_niza, "Achieved_p": Ach_p_niza, "gap": gap_niza,"plan": plan_niza, "mtd": mtd_niza, "clustername": clustername_niza, "cname": cname_niza,"status": status_niza}
        nellore = {"date": date_one, "admission": adm_nello, "Achieved_p": Ach_p_nello, "gap": gap_nello,"plan": plan_nello, "mtd": mtd_nello, "clustername": clustername_nello, "cname": cname_nello,"status": status_nello}
        viz_unit4 = {"date": date_one, "admission": adm_viz_u_4, "Achieved_p": Ach_p_viz_u_4, "gap": gap_viz_u_4,"plan": plan_viz_u_4, "mtd": mtd_viz_u_4, "clustername": clustername_viz_u_4,"cname": cname_viz_u_4, "status": status_viz_u_4}
        aurangabad = {"date": date_one, "admission": adm_aur, "Achieved_p": Ach_p_aur, "gap": gap_aur, "plan": plan_aur,"mtd": mtd_aur, "clustername": clustername_aur, "cname": cname_aur, "status": status_aur}
        sangamner = {"date": date_one, "admission": adm_sang, "Achieved_p": Ach_p_sang, "gap": gap_sang,"plan": plan_sang, "mtd": mtd_sang, "clustername": clustername_sang, "cname": cname_sang,"status": status_sang}
        kakinada = {"date": date_one, "admission": adm_kaki, "Achieved_p": Ach_p_kaki, "gap": gap_kaki,"plan": plan_kaki, "mtd": mtd_kaki, "clustername": clustername_kaki, "cname": cname_kaki,"status": status_kaki}
        mci = {"date": date_one, "admission": adm_mci, "Achieved_p": Ach_p_mci, "gap": gap_mci, "plan": plan_mci,"mtd": mtd_mci, "clustername": clustername_mci, "cname": cname_mci, "status": status_mci}
        begu = {"date": date_one, "adm": adm_begam, "Achieved_p": ach_p_begam, "plan": plan_begam, "gap": gap_begam,"mtd": mtd_begam, "clustername": clustername_begam, "cname": cname_begam, "status": status_begam}
        navimu = {"date": date_one, "adm": adm_navim, "Achieved_p": ach_p_navim, "plan": plan_navim, "gap": gap_navim,"mtd": mtd_navim, "clustername": clustername_navim, "cname": cname_navim, "status": status_navim}

        return [{"Sangareddy": sangareddy, "Kurnool": kurnool, "Vizag_unit1": viz_unit1, "Vizag Unit 3": viz_unit3,"Madhapur": madhapur, "Karimnagar": karimnagar, "Nashik": nashik, "Nizamabad": nizamabad,"Nellore": nellore, "Vizag_unit 4": viz_unit4, "Aurangabad": aurangabad, "Sangamner": sangamner,"Kakinada": kakinada, "Mci": mci, "Begumpet": begu, "NaviMumbai": navimu}]



    else:
        # query for sangareddy branch
        adm_san = db.query(models.Patient_data.adate,
                           models.Patient_data.branch,
                           models.Patient_data.ipno,
                           models.Patient_data.organization,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.consultant,
                           models.Patient_data.isbilldone)\
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Sangareddy',
                   models.Patient_data.organization != "Medicover Associate",
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'GENERAL SURGERY',
                   models.Patient_data.consultant != 'K.SRIDHAR',
                   models.Patient_data.wardname != 'DIALYSIS WARD',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled').count()
        plan_san = db.query(models.Admission.plan).where(models.Admission.date == da,models.Admission.branch == 'Sangareddy').first()
        # plan_san = plan_san.plan
        # print(plan_san)
        mtd_san = db.query(models.Patient_data.adate,
                           models.Patient_data.branch,
                           models.Patient_data.ipno,
                           models.Patient_data.organization,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.consultant,
                           models.Patient_data.isbilldone)\
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Sangareddy',
                   models.Patient_data.organization != "Medicover Associate",
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'GENERAL SURGERY',
                   models.Patient_data.consultant != 'K.SRIDHAR',
                   models.Patient_data.wardname != 'DIALYSIS WARD',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled').count()
        plan_san = plan_san.plan
        try:
            Ach_p_san = round((adm_san / plan_san) * 100, 2)
        except ZeroDivisionError:
            Ach_p_san=0

        gap_san = adm_san - plan_san
        cluster_san = db.query(models.admission_dummy.clustername, models.admission_dummy.cname, models.admission_dummy.status).filter(models.admission_dummy.branch == 'Sangareddy').first()
        clustername_san = cluster_san[0]
        cname_san = cluster_san[1]
        status_san = cluster_san[2]

        # query for Kurnool branch
        adm_k = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.consultant,
                         models.Patient_data.department,
                         models.Patient_data.wardname,
                         models.Patient_data.branch,
                         models.Patient_data.adate) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Kurnool',
                   models.Patient_data.organization != "Medicover Associate",
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DAY CARE',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_k = db.query(models.Admission.plan).where(models.Admission.date == da,models.Admission.branch == 'Kurnool').first()

        mtd_k = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.consultant,
                         models.Patient_data.department,
                         models.Patient_data.wardname,
                         models.Patient_data.branch,
                         models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Kurnool',
                   models.Patient_data.organization != "Medicover Associate",
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
                   models.Patient_data.wardname != 'DAY CARE',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_k = plan_k.plan
        try:
            Ach_p_k = round((adm_k / plan_k) * 100, 2)
        except ZeroDivisionError:
             Ach_p_k=0


        print(adm_k)
        # Ach_p_k = round((adm_k / plan_k) * 100, 2)
        gap_k = adm_k - plan_k
        cluster_k = db.query(models.admission_dummy.clustername, models.admission_dummy.cname, models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'kurnool').first()
        clustername_k = cluster_k[0]
        cname_k = cluster_k[1]
        status_k = cluster_k[2]

        # query for Vizag Unit1 branch
        adm_v = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.wardname,
                         models.Patient_data.adate, models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Vizag Unit 1',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'CRADLE WARD').count()

        plan_v = db.query(models.Admission.plan).where(models.Admission.date == da,models.Admission.branch == 'Vizag Unit 1').first()

        mtd_v = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.consultant,
                         models.Patient_data.department,
                         models.Patient_data.wardname,
                         models.Patient_data.branch,
                         models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Vizag Unit 1',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.wardname != 'CRADLE WARD',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_v = plan_v.plan
        try:
            Ach_p_v = round((adm_v / plan_v) * 100, 2)
        except ZeroDivisionError:
            Ach_p_v=0
        gap_v = adm_v - plan_v
        cluster_v = db.query(models.admission_dummy.clustername, models.admission_dummy.cname, models.admission_dummy.status).filter(models.admission_dummy.branch == 'Vizag Unit 1').first()
        clustername_v = cluster_v[0]
        cname_v = cluster_v[1]
        status_v = cluster_v[2]

        # query for vizag unit 3
        adm_viz3 = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.wardname,
                            models.Patient_data.department,
                            models.Patient_data.adate,
                            models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Vizag Unit 3',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_viz3 = db.query(models.Admission.plan).where(models.Admission.date == da, models.Admission.branch == 'Vizag Unit 3').first()
        mtd_viz3 = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.consultant,
                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.branch == 'Vizag Unit 3',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_viz3 = plan_viz3.plan
        try:
            Ach_p_viz3 = round((adm_viz3 / plan_viz3) * 100, 2)
        except ZeroDivisionError:
            Ach_p_viz3=0
        gap_viz3 = adm_viz3 - plan_viz3

        cluster_viz3 = db.query(models.admission_dummy.clustername, models.admission_dummy.cname, models.admission_dummy.status).filter(models.admission_dummy.branch == 'Vizag Unit 3').first()
        clustername_viz3 = cluster_viz3[0]
        cname_viz3 = cluster_viz3[1]
        status_viz3 = cluster_viz3[2]

        # query for Madhapur branch
        adm_m = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.wardname,
                         models.Patient_data.department,
                         models.Patient_data.adate,
                         models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Madhapur',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_m = db.query(models.Admission.plan).where(models.Admission.date == da, models.Admission.branch == 'Madhapur').first()
        mtd_m = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.consultant,
                         models.Patient_data.department,
                         models.Patient_data.wardname,
                         models.Patient_data.branch,
                         models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.branch == 'Madhapur',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_m = plan_m.plan
        try:
            Ach_p_m = round((adm_m / plan_m) * 100, 2)
        except ZeroDivisionError:
            Ach_p_m=0
        gap_m = adm_m - plan_m

        cluster_m = db.query(models.admission_dummy.clustername, models.admission_dummy.cname, models.admission_dummy.status).filter(models.admission_dummy.branch == 'Madhapur').first()
        clustername_m = cluster_m[0]
        cname_m = cluster_m[1]
        status_m = cluster_m[2]

        # query for Karimnagar branch
        adm_karim = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.wardname,
                             models.Patient_data.department,
                             models.Patient_data.adate,
                             models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Karimnagar',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_karim = db.query(models.Admission.plan).where(models.Admission.date == da, models.Admission.branch == 'Karimnagar').first()
        mtd_karim = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.consultant,
                             models.Patient_data.department,
                             models.Patient_data.wardname,
                             models.Patient_data.branch,
                             models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.branch == 'Karimnagar',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_karim = plan_karim.plan
        try:
            Ach_p_karim = round((adm_m / plan_m) * 100, 2)
        except ZeroDivisionError:
            Ach_p_karim=0
        gap_karim = adm_m - plan_m

        cluster_karim = db.query(models.admission_dummy.clustername, models.admission_dummy.cname, models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Karimnagar').first()
        clustername_karim = cluster_karim[0]
        cname_karim = cluster_karim[1]
        status_karim = cluster_karim[2]

        # query for Nashik branch
        adm_nash = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.wardname,
                            models.Patient_data.department,
                            models.Patient_data.adate,
                            models.Patient_data.branch) \
            .where(models.Patient_data.adate == date_one,
                   models.Patient_data.branch == 'Nashik',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_nash = db.query(models.Admission.plan).where(models.Admission.date == da, models.Admission.branch == 'Nashik').first()
        mtd_nash = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.branch == 'Nashik',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_nash = plan_nash.plan
        try:
            Ach_p_nash = round((adm_nash / plan_nash) * 100, 2)
        except ZeroDivisionError:
            Ach_p_nash=0
        gap_nash = adm_nash - plan_nash

        cluster_nash = db.query(models.admission_dummy.clustername, models.admission_dummy.cname, models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Nashik').first()
        clustername_nash = cluster_nash[0]
        cname_nash = cluster_nash[1]
        status_nash = cluster_nash[2]

        # query for Nizamabad branch
        adm_niza = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.wardname,
                            models.Patient_data.department,
                            models.Patient_data.adate,
                            models.Patient_data.branch) \
            .where(models.Patient_data.adate == date_one,
                   models.Patient_data.branch == 'Nizamabad',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_niza = db.query(models.Admission.plan).where(models.Admission.date == da,models.Admission.branch == 'Nizamabad').first()
        mtd_niza = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Nizamabad',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_niza = plan_niza.plan
        try:
            Ach_p_niza = round((adm_niza / plan_niza) * 100, 2)
        except ZeroDivisionError:
            Ach_p_niza=0
        gap_niza = adm_niza - plan_niza

        cluster_niza = db.query(models.admission_dummy.clustername, models.admission_dummy.cname, models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Nellore').first()
        clustername_niza = cluster_niza[0]
        cname_niza = cluster_niza[1]
        status_niza = cluster_niza[2]

        # query for Nellore branch
        adm_nello = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.wardname,
                             models.Patient_data.department,
                             models.Patient_data.adate,
                             models.Patient_data.branch) \
            .where(models.Patient_data.adate == date_one,
                   models.Patient_data.branch == 'Nellore',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_nello = db.query(models.Admission.plan).where(models.Admission.date == da, models.Admission.branch == 'Nellore').first()
        mtd_nello = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.consultant,
                             models.Patient_data.department,
                             models.Patient_data.wardname,
                             models.Patient_data.branch,
                             models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Nellore',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_nello = plan_nello.plan
        try:
            Ach_p_nello = round((adm_nello / plan_nello) * 100, 2)
        except ZeroDivisionError:
            Ach_p_nello=0
        gap_nello = adm_nello - plan_nello

        cluster_nello = db.query(models.admission_dummy.clustername, models.admission_dummy.cname, models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Nellore').first()
        clustername_nello = cluster_nello[0]
        cname_nello = cluster_nello[1]
        status_nello = cluster_nello[2]

        # query for vizag unit 4
        adm_viz_u_4 = db.query(models.Patient_data.admntype,
                               models.Patient_data.ipno,
                               models.Patient_data.isbilldone,
                               models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Vizag Unit 4',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.admntype != 'D').count()

        plan_viz_u_4 = db.query(models.Admission.plan).where(models.Admission.date == da,  models.Admission.branch == 'Vizag Unit 4').first()

        mtd_viz_u_4 = db.query(models.Patient_data.admntype,
                               models.Patient_data.ipno,
                               models.Patient_data.isbilldone,
                               models.Patient_data.branch,
                               models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Vizag Unit 4',
                   models.Patient_data.admntype != 'D',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_viz_u_4 = plan_viz_u_4.plan
        try:
            Ach_p_viz_u_4 = round((adm_viz_u_4 / plan_viz_u_4) * 100, 2)
        except ZeroDivisionError:
            Ach_p_viz_u_4=0
        gap_viz_u_4 = adm_viz_u_4 - plan_viz_u_4
        cluster_viz_u_4 = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,  models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Vizag Unit 4').first()
        clustername_viz_u_4 = cluster_viz_u_4[0]
        cname_viz_u_4 = cluster_viz_u_4[1]
        status_viz_u_4 = cluster_viz_u_4[2]

        # query for Aurangabad branch
        adm_aur = db.query(models.Patient_data.admntype,
                           models.Patient_data.ipno,
                           models.Patient_data.isbilldone,
                           models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Aurangabad',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.admntype != 'D').count()

        plan_aur = db.query(models.Admission.plan).where(models.Admission.date == da, models.Admission.branch == 'Aurangabad').first()

        mtd_aur = db.query(models.Patient_data.admntype,
                           models.Patient_data.ipno,
                           models.Patient_data.isbilldone,
                           models.Patient_data.branch,
                           models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Aurangabad',

                   models.Patient_data.admntype != 'D',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_aur = plan_aur.plan
        try:
            Ach_p_aur = round((adm_aur / plan_aur) * 100, 2)
        except ZeroDivisionError:
            Ach_p_aur=0
        gap_aur = adm_aur - plan_aur
        cluastrer_aur = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Aurangabad').first()
        clustername_aur = cluastrer_aur[0]
        cname_aur = cluastrer_aur[1]
        status_aur = cluastrer_aur[2]

        # query for Sangamner branch
        adm_sang = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.wardname,
                            models.Patient_data.adate,
                            models.Patient_data.branch) \
            .where(models.Patient_data.adate == date_one,
                   models.Patient_data.branch == 'Sangamner',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',

                   models.Patient_data.wardname != 'DIALYSIS WARD').count()

        plan_sang = db.query(models.Admission.plan).where(models.Admission.date == da, models.Admission.branch == 'Sangamner').first()
        mtd_sang = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.consultant,
                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Sangamner',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.wardname != 'DIALYSIS WARD',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        plan_sang = plan_sang.plan
        try:
            Ach_p_sang = round((adm_sang / plan_sang) * 100, 2)
        except ZeroDivisionError:
            Ach_p_sang=0
        gap_sang = adm_sang - plan_sang

        cluster_sang = db.query(models.admission_dummy.clustername, models.admission_dummy.cname, models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Sangamner').first()
        clustername_sang = cluster_sang[0]
        cname_sang = cluster_sang[1]
        status_sang = cluster_sang[2]

        # query for Kakinada branch
        adm_kaki = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.wardname,
                            models.Patient_data.department,
                            models.Patient_data.adate,
                            models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Kakinada',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_kaki = db.query(models.Admission.plan).where(models.Admission.date == da, models.Admission.branch == 'Kakinada').first()

        mtd_kaki = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.consultant,
                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Kakinada',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        plan_kaki = plan_kaki.plan
        try:
            Ach_p_kaki = round((adm_kaki / plan_kaki) * 100, 2)
        except ZeroDivisionError:
            Ach_p_kaki=0
        gap_kaki = adm_kaki - plan_kaki

        cluster_kaki = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Kakinada').first()
        clustername_kaki = cluster_kaki[0]
        cname_kaki = cluster_kaki[1]
        status_kaki = cluster_kaki[2]

        # query for Mci branch
        adm_mci = db.query(models.Patient_data.organization,
                           models.Patient_data.ipno,
                           models.Patient_data.isbilldone,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.adate,
                           models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Mci',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.wardname != 'DIALY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.department != 'RADIATION ONCOLOGY').count()

        plan_mci = db.query(models.Admission.plan).where(models.Admission.date == da, models.Admission.branch == 'Mci').first()

        mtd_mci = db.query(models.Patient_data.organization,
                           models.Patient_data.ipno,
                           models.Patient_data.isbilldone,
                           models.Patient_data.consultant,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.branch,
                           models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Mci',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.wardname != 'DIALY',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_mci = plan_mci.plan
        try:
            Ach_p_mci = round((adm_mci / plan_mci) * 100, 2)
        except ZeroDivisionError:
            Ach_p_mci=0
        gap_mci = adm_mci - plan_mci

        cluster_mci = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(models.admission_dummy.branch == 'Mci').first()
        clustername_mci = cluster_mci[0]
        cname_mci = cluster_mci[1]
        status_mci = cluster_mci[2]

        # query for begampet
        adm_begam = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.wardname,
                             models.Patient_data.adate,
                             models.Patient_data.branch) \
            .where(models.Patient_data.adate == date_one,
                   models.Patient_data.branch == 'Begumpet',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS WARD').count()

        plan_begam = 60
        ach_p_begam = round((adm_begam / plan_begam) * 100, 2)
        gap_begam = adm_begam - plan_begam
        mtd_begam = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.consultant,
                             models.Patient_data.department,
                             models.Patient_data.wardname,
                             models.Patient_data.branch,
                             models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Begumpet',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.wardname != 'DIALY',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        clustername_begam = 'Megha'
        cname_begam = 'ROTA'
        status_begam = 'Active'

        # query for navimumbai
        adm_navim = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.wardname,
                             models.Patient_data.adate,
                             models.Patient_data.branch) \
            .where(models.Patient_data.adate == date_one,
                   models.Patient_data.branch == 'Navi Mumbai',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS WARD').count()

        plan_navim = 60
        try:
            ach_p_navim = round((adm_navim / plan_navim) * 100, 2)
        except ZeroDivisionError:
            ach_p_navim=0
        gap_navim = adm_navim - plan_navim
        mtd_navim = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.consultant,
                             models.Patient_data.department,
                             models.Patient_data.wardname,
                             models.Patient_data.branch,
                             models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Begumpet',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.wardname != 'DIALY',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        clustername_navim = 'Sachin'
        cname_navim = 'Maharastra'
        status_navim = 'Active'


        sangareddy = {"date": date_one, "admission": adm_san, "Achieved_p": Ach_p_san, "gap": gap_san,"plan": plan_san,"mtd": mtd_san, "clustername": clustername_san, "cname": cname_san, "status": status_san}
        kurnool = {"date": date_one, "admission": adm_k, "Achieved_p": Ach_p_k, "gap": gap_k, "plan": plan_k, "mtd": mtd_k, "clustername": clustername_k, "cname": cname_k, "status": status_k}
        viz_unit1 = {"date": date_one, "admission": adm_v, "Achieved_p": Ach_p_v, "gap": gap_v, "plan": plan_v, "mtd": mtd_v, "clustername": clustername_v, "cname": cname_v, "status": status_v}
        viz_unit3 = {"date": date_one, "admission": adm_viz3, "Achieved_p": Ach_p_viz3, "gap": gap_viz3, "plan": plan_viz3, "mtd": mtd_viz3, "clustername": clustername_viz3, "cname": cname_viz3,"status": status_viz3}
        madhapur = {"date": date_one, "admission": adm_m, "Achieved_p": Ach_p_m, "gap": gap_m, "plan": plan_m,"mtd": mtd_m, "clustername": clustername_m, "cname": cname_m, "status": status_m}
        karimnagar = {"date": date_one, "admission": adm_karim, "Achieved_p": Ach_p_karim, "gap": gap_karim, "plan": plan_karim, "mtd": mtd_karim, "clustername": clustername_karim, "cname": cname_karim, "status": status_karim}
        nashik = {"date": date_one, "admission": adm_nash, "Achieved_p": Ach_p_nash, "gap": gap_nash, "plan": plan_nash, "mtd": mtd_nash, "clustername": clustername_nash, "cname": cname_nash, "status": status_nash}
        nizamabad = {"date": date_one, "admission": adm_niza, "Achieved_p": Ach_p_niza, "gap": gap_niza,"plan": plan_niza, "mtd": mtd_niza, "clustername": clustername_niza, "cname": cname_niza,"status": status_niza}
        nellore = {"date": date_one, "admission": adm_nello, "Achieved_p": Ach_p_nello, "gap": gap_nello,"plan": plan_nello, "mtd": mtd_nello, "clustername": clustername_nello, "cname": cname_nello, "status": status_nello}
        viz_unit4 = {"date": date_one, "admission": adm_viz_u_4, "Achieved_p": Ach_p_viz_u_4, "gap": gap_viz_u_4,"plan": plan_viz_u_4, "mtd": mtd_viz_u_4, "clustername": clustername_viz_u_4,"cname": cname_viz_u_4, "status": status_viz_u_4}
        aurangabad = {"date": date_one, "admission": adm_aur, "Achieved_p": Ach_p_aur, "gap": gap_aur, "plan": plan_aur, "mtd": mtd_aur, "clustername": clustername_aur, "cname": cname_aur, "status": status_aur}
        sangamner = {"date": date_one, "admission": adm_sang, "Achieved_p": Ach_p_sang, "gap": gap_sang, "plan": plan_sang, "mtd": mtd_sang, "clustername": clustername_sang, "cname": cname_sang,"status": status_sang}
        kakinada = {"date": date_one, "admission": adm_kaki, "Achieved_p": Ach_p_kaki, "gap": gap_kaki,"plan": plan_kaki, "mtd": mtd_kaki, "clustername": clustername_kaki, "cname": cname_kaki,"status": status_kaki}
        mci = {"date": date_one, "admission": adm_mci, "Achieved_p": Ach_p_mci, "gap": gap_mci, "plan": plan_mci,"mtd": mtd_mci, "clustername": clustername_mci, "cname": cname_mci, "status": status_mci}
        bega = {"date": date_one, "adm": adm_begam, "Achieved_p": ach_p_begam, "plan": plan_begam, "gap": gap_begam,"mtd": mtd_begam, "clustername": clustername_begam, "cname": cname_begam, "status": status_begam}
        navimu = {"date": date_one, "adm": adm_navim, "Achieved_p": ach_p_navim, "plan": plan_navim, "gap": gap_navim,"mtd": mtd_navim, "clustername": clustername_navim, "cname": cname_navim, "status": status_navim}

        return [{"Sangareddy": sangareddy, "Kurnool": kurnool, "Vizag_unit1": viz_unit1, "Vizag Unit 3": viz_unit3,"Madhapur": madhapur, "Karimnagar": karimnagar, "Nashik": nashik, "Nizamabad": nizamabad, "Nellore": nellore, "Vizag_unit 4": viz_unit4, "Aurangabad": aurangabad, "Sangamner": sangamner,"Kakinada": kakinada, "Mci": mci, "Begumpet": bega, "Navi Mumbai": navimu}]


@app.post('/read branch details', tags=['admission api'])
def read(date_one:str, mtd_date:str,branch:str, db:Session=Depends(get_db),credentials: HTTPBasicCredentials = Depends(security)):

    x = datetime.strftime(parser.parse(date_one), '%d, %b %Y')
    print(x, type(x))
    da = datetime.strptime(x, '%d, %b %Y').date()
    print(da, type(da))
    # new= datetime.strftime(parser.parse(date_one),format)
    # print(new,type(new))

    y = datetime.strftime(parser.parse(mtd_date), '%d, %b %Y')
    mtd_dat = datetime.strptime(y, '%d, %b %Y').date()
    print(mtd_dat)
    u_user_m = da.month
    v_user_y = da.year
    print(u_user_m, v_user_y)
    print(mtd_dat.month)

    date_str = '2022-08-01'
    f = datetime.strftime(parser.parse(date_str), '%d, %b %Y')
    fa = datetime.strptime(f, '%d, %b %Y').date()
    c_month = fa.month
    print(c_month, type(c_month))
    c_year = fa.year
    print(c_year, type(c_year))

    if (u_user_m < c_month):
        adm_san = db.query(models.Patient_data.adate,
                           models.Patient_data.branch,
                           models.Patient_data.ipno,
                           models.Patient_data.organization,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.consultant,
                           models.Patient_data.isbilldone) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Sangareddy',
                   models.Patient_data.organization != "Medicover Associate%",
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'GENERAL SURGERY',
                   models.Patient_data.consultant != 'K.SRIDHAR',
                   models.Patient_data.wardname != 'DIALYSIS WARD',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled').count()
        plan_san = 60

        mtd_san = db.query(models.Patient_data.adate,
                           models.Patient_data.branch,
                           models.Patient_data.ipno,
                           models.Patient_data.organization,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.consultant,
                           models.Patient_data.isbilldone) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Sangareddy',
                   models.Patient_data.organization != "Medicover Associate%",
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'GENERAL SURGERY',
                   models.Patient_data.consultant != 'K.SRIDHAR',
                   models.Patient_data.wardname != 'DIALYSIS WARD',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled').count()
        try:
            Ach_p_san = round((adm_san / plan_san) * 100, 2)
        except ZeroDivisionError:
            Ach_p_san=0
        gap_san = adm_san - plan_san
        cluster_san = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                               models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Sangareddy').first()
        clustername_san = cluster_san[0]
        cname_san = cluster_san[1]
        status_san = cluster_san[2]

        # query for Kurnool branch
        adm_k = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.consultant,
                         models.Patient_data.department,
                         models.Patient_data.wardname,
                         models.Patient_data.branch,
                         models.Patient_data.adate) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Kurnool',
                   models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
                   models.Patient_data.wardname != 'DAY CARE',
                   models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DAY CARE',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_k = 60
        mtd_k = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.consultant,
                         models.Patient_data.department,
                         models.Patient_data.wardname,
                         models.Patient_data.branch,
                         models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Kurnool',
                   models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
                   models.Patient_data.wardname != 'DAY CARE',
                   models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DAY CARE',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        try:
            Ach_p_k = round((adm_k / plan_k) * 100, 2)
        except ZeroDivisionError:
            Ach_p_k=0
        gap_k = adm_k - plan_k
        cluster_k = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                             models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'kurnool').first()
        clustername_k = cluster_k[0]
        cname_k = cluster_k[1]
        status_k = cluster_k[2]

        # query for Vizag Unit1 branch
        adm_v = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.wardname,
                         models.Patient_data.adate, models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Vizag Unit 1',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'CRADLE WARD').count()

        plan_v = 60
        mtd_v = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.consultant,
                         models.Patient_data.department,
                         models.Patient_data.wardname,
                         models.Patient_data.branch,
                         models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Vizag Unit 1',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.wardname != 'CRADLE WARD',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        try:
            Ach_p_v = round((adm_v / plan_v) * 100, 2)
        except ZeroDivisionError:
            Ach_p_v=0
        gap_v = adm_v - plan_v
        cluster_v = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                             models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Vizag Unit 1').first()
        clustername_v = cluster_v[0]
        cname_v = cluster_v[1]
        status_v = cluster_v[2]

        # query for vizag unit 3
        adm_viz3 = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.wardname,
                            models.Patient_data.department,
                            models.Patient_data.adate,
                            models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Vizag Unit 3',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_viz3 = 60
        mtd_viz3 = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.consultant,
                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.branch == 'Vizag Unit 3',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        try:
            Ach_p_viz3 = round((adm_viz3 / plan_viz3) * 100, 2)
        except ZeroDivisionError:
            Ach_p_viz3=0
        gap_viz3 = adm_viz3 - plan_viz3

        cluster_viz3 = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                                models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Vizag Unit 3').first()
        clustername_viz3 = cluster_viz3[0]
        cname_viz3 = cluster_viz3[1]
        status_viz3 = cluster_viz3[2]

        # query for Madhapur branch
        adm_m = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.wardname,
                         models.Patient_data.department,
                         models.Patient_data.adate,
                         models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Madhapur',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_m = 60
        mtd_m = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.consultant,
                         models.Patient_data.department,
                         models.Patient_data.wardname,
                         models.Patient_data.branch,
                         models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Madhapur',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        try:
            Ach_p_m = round((adm_m / plan_m) * 100, 2)
        except ZeroDivisionError:
            Ach_p_m=0
        gap_m = adm_m - plan_m

        cluster_m = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                             models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Madhapur').first()
        clustername_m = cluster_m[0]
        cname_m = cluster_m[1]
        status_m = cluster_m[2]

        # query for Karimnagar branch
        adm_karim = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.wardname,
                             models.Patient_data.department,
                             models.Patient_data.adate,
                             models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Karimnagar',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_karim = 60
        mtd_karim = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.consultant,
                             models.Patient_data.department,
                             models.Patient_data.wardname,
                             models.Patient_data.branch,
                             models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Karimnagar',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        try:
            Ach_p_karim = round((adm_m / plan_m) * 100, 2)
        except ZeroDivisionError:
            Ach_p_karim=0
        gap_karim = adm_m - plan_m

        cluster_karim = db.query(models.admission_dummy.clustername, models.admission_dummy.cname, models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Karimnagar').first()
        clustername_karim = cluster_karim[0]
        cname_karim = cluster_karim[1]
        status_karim = cluster_karim[2]

        # query for Nashik branch
        adm_nash = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.wardname,
                            models.Patient_data.department,
                            models.Patient_data.adate,
                            models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Nashik',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_nash = 60
        mtd_nash = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.consultant,
                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate)\
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Nashik',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        try:
            Ach_p_nash = round((adm_nash / plan_nash) * 100, 2)
        except ZeroDivisionError:
            Ach_p_nash=0
        gap_nash = adm_nash - plan_nash

        cluster_nash = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                                models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Nashik').first()
        clustername_nash = cluster_nash[0]
        cname_nash = cluster_nash[1]
        status_nash = cluster_nash[2]

        # query for Nizamabad branch
        adm_niza = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.wardname,
                            models.Patient_data.department,
                            models.Patient_data.adate,
                            models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Nizamabad',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_niza =60
        mtd_niza = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.consultant,
                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Nizamabad',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        try:
            Ach_p_niza = round((adm_niza / plan_niza) * 100, 2)
        except ZeroDivisionError:
            Ach_p_niza=0
        gap_niza = adm_niza - plan_niza

        cluster_niza = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Nellore').first()
        clustername_niza = cluster_niza[0]
        cname_niza = cluster_niza[1]
        status_niza = cluster_niza[2]

        # query for Nellore branch
        adm_nello = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.wardname,
                             models.Patient_data.department,
                             models.Patient_data.adate,
                             models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Nellore',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_nello = 60
        mtd_nello = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.consultant,
                             models.Patient_data.department,
                             models.Patient_data.wardname,
                             models.Patient_data.branch,
                             models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Nellore',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        try:
            Ach_p_nello = round((adm_nello / plan_nello) * 100, 2)
        except ZeroDivisionError:
            Ach_p_nello=0
        gap_nello = adm_nello - plan_nello

        cluster_nello = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                                 models.admission_dummy.status).filter(models.admission_dummy.branch == 'Nellore').first()
        clustername_nello = cluster_nello[0]
        cname_nello = cluster_nello[1]
        status_nello = cluster_nello[2]

        # query for vizag unit 4
        adm_viz_u_4 = db.query(models.Patient_data.admntype,
                               models.Patient_data.ipno,
                               models.Patient_data.isbilldone,
                               models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Vizag Unit 4',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.admntype != 'D').count()

        plan_viz_u_4 =60

        mtd_viz_u_4 = db.query(models.Patient_data.admntype,
                               models.Patient_data.ipno,
                               models.Patient_data.isbilldone,
                               models.Patient_data.branch,
                               models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Vizag Unit 4',
                   models.Patient_data.admntype != 'D',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        try:
            Ach_p_viz_u_4 = round((adm_viz_u_4 / plan_viz_u_4) * 100, 2)
        except ZeroDivisionError:
            Ach_p_viz_u_4=0
        gap_viz_u_4 = adm_viz_u_4 - plan_viz_u_4
        cluster_viz_u_4 = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(models.admission_dummy.branch == 'Vizag Unit 4').first()
        clustername_viz_u_4 = cluster_viz_u_4[0]
        cname_viz_u_4 = cluster_viz_u_4[1]
        status_viz_u_4 = cluster_viz_u_4[2]

        # query for Aurangabad branch
        adm_aur = db.query(models.Patient_data.admntype,
                           models.Patient_data.ipno,
                           models.Patient_data.isbilldone,
                           models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Aurangabad',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.admntype != 'D').count()

        plan_aur = 60
        mtd_aur = db.query(models.Patient_data.organization,
                           models.Patient_data.ipno,
                           models.Patient_data.isbilldone,
                           models.Patient_data.consultant,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.branch,
                           models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Aurangabad',

                   models.Patient_data.admntype != 'D',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        try:
            Ach_p_aur = round((adm_aur / plan_aur) * 100, 2)
        except ZeroDivisionError:
            Ach_p_aur=0
        gap_aur = adm_aur - plan_aur
        cluastrer_aur = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                                 models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Aurangabad').first()
        clustername_aur = cluastrer_aur[0]
        cname_aur = cluastrer_aur[1]
        status_aur = cluastrer_aur[2]

        # query for Sangamner branch
        adm_sang = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.wardname,
                            models.Patient_data.adate,
                            models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Sangamner',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS WARD').count()

        plan_sang = 60
        mtd_sang = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.consultant,
                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Sangamner',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.wardname != 'DIALYSIS WARD',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        try:
            Ach_p_sang = round((adm_sang / plan_sang) * 100, 2)
        except ZeroDivisionError:
            Ach_p_sang=0
        gap_sang = adm_sang - plan_sang

        cluster_sang = db.query(models.admission_dummy.clustername, models.admission_dummy.cname, models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Sangamner').first()
        clustername_sang = cluster_sang[0]
        cname_sang = cluster_sang[1]
        status_sang = cluster_sang[2]

        # query for Kakinada branch
        adm_kaki = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.wardname,
                            models.Patient_data.department,
                            models.Patient_data.adate,
                            models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Kakinada',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_kaki =60

        mtd_kaki = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,

                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Kakinada',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        try:
            Ach_p_kaki = round((adm_kaki / plan_kaki) * 100, 2)
        except ZeroDivisionError:
            Ach_p_kaki=0
        gap_kaki = adm_kaki - plan_kaki

        cluster_kaki = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                                models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Kakinada').first()
        clustername_kaki = cluster_kaki[0]
        cname_kaki = cluster_kaki[1]
        status_kaki = cluster_kaki[2]

        # query for Mci branch
        adm_mci = db.query(models.Patient_data.organization,
                           models.Patient_data.ipno,
                           models.Patient_data.isbilldone,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.adate,
                           models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Mci',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.wardname != 'DIALY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.department != 'RADIATION ONCOLOGY').count()

        plan_mci = 60

        mtd_mci = db.query(models.Patient_data.organization,
                           models.Patient_data.ipno,
                           models.Patient_data.isbilldone,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.branch,
                           models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Mci',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.wardname != 'DIALY',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        try:
            Ach_p_mci = round((adm_mci / plan_mci) * 100, 2)
        except ZeroDivisionError:
            Ach_p_mci=0
        gap_mci = adm_mci - plan_mci

        cluster_mci = db.query(models.admission_dummy.clustername, models.admission_dummy.cname, models.admission_dummy.status).filter(models.admission_dummy.branch == 'Mci').first()
        clustername_mci = cluster_mci[0]
        cname_mci = cluster_mci[1]
        status_mci = cluster_mci[2]

        # query for begumpet
        adm_begam = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.wardname,
                             models.Patient_data.adate,
                             models.Patient_data.branch) \
            .where(models.Patient_data.adate == date_one,
                   models.Patient_data.branch == 'Begumpet',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS WARD').count()
        ach_p_begam = round((adm_mci / plan_mci) * 100, 2)
        plan_begam = 60
        gap_begam = adm_begam - plan_begam
        mtd_begam = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.consultant,
                             models.Patient_data.department,
                             models.Patient_data.wardname,
                             models.Patient_data.branch,
                             models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Begumpet',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.wardname != 'DIALY',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        clustername_begam = 'Megha'
        cname_begam = 'ROTA'
        status_begam = 'Active'

        # query for navimumbai
        adm_navim = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.wardname,
                             models.Patient_data.adate,
                             models.Patient_data.branch) \
            .where(models.Patient_data.adate == date_one,
                   models.Patient_data.branch == 'Navi Mumbai',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS WARD').count()
        ach_p_navim = round((adm_mci / plan_mci) * 100, 2)
        plan_navim = 60
        gap_navim = adm_navim - plan_navim
        mtd_navim = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.consultant,
                             models.Patient_data.department,
                             models.Patient_data.wardname,
                             models.Patient_data.branch,
                             models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Begumpet',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.wardname != 'DIALY',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        clustername_navim = 'Sachin'
        cname_navim = 'Maharastra'
        status_navim = 'Active'

        if branch=='Sangareddy':
           # print(branch)
           if branch[0] =='S' in branch:
               branch[0].lower()
               return {"branch":branch,"date":date_one, "adm":adm_san, "Achieved_p":Ach_p_san, "plan":plan_san,"gap":gap_san, "mtd":mtd_san, "clustername":clustername_san,"cname":cname_san,"status":status_san}
        else:
            return {"branch":branch,"date":date_one, "adm":adm_san, "Achieved_p":Ach_p_san, "plan":plan_san,"gap":gap_san, "mtd":mtd_san, "clustername":clustername_san,"cname":cname_san,"status":status_san}

        if branch=='Kurnool':
            # if branch
            return {"branch":branch,"date":date_one, "adm":adm_k, "Achieved_p":Ach_p_k, "plan":plan_k,"gap":gap_k, "mtd":mtd_k, "clustername":clustername_k,"cname":cname_k,"status":status_k}

        if branch=='Vizag Unit 1':
            return {"branch":branch,"date":date_one, "adm": adm_v, "Achieved_p": Ach_p_v, "plan": plan_v,"gap": gap_v, "mtd": mtd_v, "clustername": clustername_v, "cname": cname_v,"status": status_v}

        if branch=='Vizag Unit 3':
            return {"branch":branch,"date":date_one, "adm": adm_viz3, "Achieved_p": Ach_p_viz3, "plan": plan_viz3,"gap": gap_viz3, "mtd": mtd_viz3, "clustername": clustername_viz3, "cname": cname_viz3,"status": status_viz3}

        if branch=='Madhapur':
            return {"branch":branch,"date":date_one, "adm": adm_m, "Achieved_p": Ach_p_m, "plan": plan_m, "gap": gap_m,"mtd": mtd_m, "clustername": clustername_m, "cname": cname_m, "status": status_m}

        if branch=='Karimnagar':
            return {"branch":branch,"date":date_one, "adm": adm_karim, "Achieved_p": Ach_p_karim, "plan": plan_karim, "gap": gap_karim,"mtd": mtd_karim, "clustername": clustername_karim, "cname": cname_karim, "status": status_karim}

        if branch=='Nashik':
            return {"branch":branch,"date":date_one, "adm": adm_nash, "Achieved_p": Ach_p_nash, "plan": plan_nash, "gap": gap_nash,"mtd": mtd_nash, "clustername": clustername_nash, "cname": cname_nash, "status": status_nash}

        if branch=='Nizamabad':
            return {"branch":branch,"date":date_one, "adm": adm_niza, "Achieved_p": Ach_p_niza, "plan": plan_niza, "gap": gap_niza,"mtd": mtd_niza, "clustername": clustername_niza, "cname": cname_niza, "status": status_niza}

        if branch=='Nellore':
            return {"branch":branch,"date":date_one, "adm": adm_nello, "Achieved_p": Ach_p_nello, "plan": plan_nello, "gap": gap_nello,"mtd": mtd_nello, "clustername": clustername_nello, "cname": cname_nello, "status": status_nello}

        if branch=='Vizag Unit 4':
            return {"branch":branch,"date":date_one, "adm": adm_viz_u_4, "Achieved_p": Ach_p_viz_u_4, "plan": plan_viz_u_4, "gap": gap_viz_u_4,"mtd": mtd_viz_u_4, "clustername": clustername_viz_u_4, "cname": cname_viz_u_4, "status": status_viz_u_4}

        if branch=='Aurangabad':
            return {"branch":branch,"date":date_one, "adm": adm_aur, "Achieved_p": Ach_p_aur, "plan": plan_aur, "gap": gap_aur,"mtd": mtd_aur, "clustername": clustername_aur, "cname": cname_aur, "status": status_aur}

        if branch=='Sangamner':
            return {"branch":branch,"date":date_one, "adm": adm_sang, "Achieved_p": Ach_p_sang, "plan": plan_sang, "gap": gap_sang,"mtd": mtd_sang, "clustername": clustername_sang, "cname": cname_sang, "status": status_sang}

        if branch=='Kakinada':
            return {"branch":branch,"date":date_one, "adm": adm_kaki, "Achieved_p": Ach_p_kaki, "plan": plan_kaki, "gap": gap_kaki,"mtd": mtd_kaki, "clustername": clustername_kaki, "cname": cname_kaki, "status": status_kaki}

        if branch=='Mci':
            return {"branch":branch,"date":date_one, "adm": adm_mci, "Achieved_p": Ach_p_mci, "plan": plan_mci,"gap": gap_mci, "mtd": mtd_mci, "clustername": clustername_mci, "cname": cname_mci,"status": status_mci}

        if branch=='Begumpet':
            return {"branch":branch,"date":date_one, "adm": adm_begam, "Achieved_p": ach_p_begam, "plan": plan_begam, "gap": gap_begam,"mtd": mtd_begam, "clustername": clustername_begam, "cname": cname_begam, "status": status_begam}

        if branch=='NaviMumbai':
            return {"branch":branch,"date":date_one, "adm": adm_navim, "Achieved_p": ach_p_navim, "plan": plan_navim, "gap": gap_navim,"mtd": mtd_navim, "clustername": clustername_navim, "cname": cname_navim, "status": status_navim}

        # if(u_cons_m >= x_user_m and v_cons_y <= y_user_y):
    else:
            # query for sangareddy branch
        adm_san = db.query(models.Patient_data.adate,
                           models.Patient_data.branch,
                           models.Patient_data.ipno,
                           models.Patient_data.organization,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.consultant,
                           models.Patient_data.isbilldone) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Sangareddy',
                   models.Patient_data.organization != "Medicover Associate%",
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'GENERAL SURGERY',
                   models.Patient_data.consultant != 'K.SRIDHAR',
                   models.Patient_data.wardname != 'DIALYSIS WARD',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled').count()
        plan_san = db.query(models.Admission.plan).where(models.Admission.date == da, models.Admission.branch == 'Sangareddy').first()
        plan_san = plan_san.plan

        mtd_san = db.query(models.Patient_data.adate,
                           models.Patient_data.branch,
                           models.Patient_data.ipno,
                           models.Patient_data.organization,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.consultant,
                           models.Patient_data.isbilldone) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Sangareddy',
                   models.Patient_data.organization != "Medicover Associate%",
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'GENERAL SURGERY',
                   models.Patient_data.consultant != 'K.SRIDHAR',
                   models.Patient_data.wardname != 'DIALYSIS WARD',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled').count()

        try:
            Ach_p_san = round((adm_san / plan_san) * 100, 2)
        except ZeroDivisionError:
            Ach_p_san=0
        gap_san = adm_san - plan_san
        cluster_san = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Sangareddy').first()
        clustername_san = cluster_san[0]
        cname_san = cluster_san[1]
        status_san = cluster_san[2]

        # query for Kurnool branch
        adm_k = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.consultant,
                         models.Patient_data.department,
                         models.Patient_data.wardname,
                         models.Patient_data.branch,
                         models.Patient_data.adate) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Kurnool',
                   models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
                   models.Patient_data.wardname != 'DAY CARE',
                   models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DAY CARE',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_k = db.query(models.Admission.plan).where(models.Admission.date == da,  models.Admission.branch == 'Kurnool').first()

        mtd_k = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.consultant,
                         models.Patient_data.department,
                         models.Patient_data.wardname,
                         models.Patient_data.branch,
                         models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Kurnool',
                   models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
                   models.Patient_data.wardname != 'DAY CARE',
                   models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DAY CARE',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_k = plan_k.plan
        try:
            Ach_p_k = round((adm_k / plan_k) * 100, 2)
        except ZeroDivisionError:
            Ach_p_k=0
        gap_k = adm_k - plan_k
        cluster_k = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'kurnool').first()
        clustername_k = cluster_k[0]
        cname_k = cluster_k[1]
        status_k = cluster_k[2]

        # query for Vizag Unit1 branch
        adm_v = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.wardname,
                         models.Patient_data.adate, models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Vizag Unit 1',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'CRADLE WARD').count()

        plan_v = db.query(models.Admission.plan).where(models.Admission.date == da, models.Admission.branch == 'Vizag Unit 1').first()

        mtd_v = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.consultant,
                         models.Patient_data.department,
                         models.Patient_data.wardname,
                         models.Patient_data.branch,
                         models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Vizag Unit 1',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.wardname != 'CRADLE WARD',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_v = plan_v.plan
        try:
            Ach_p_v = round((adm_v / plan_v) * 100, 2)
        except ZeroDivisionError:
            Ach_p_v=0
        gap_v = adm_v - plan_v
        cluster_v = db.query(models.admission_dummy.clustername, models.admission_dummy.cname, models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Vizag Unit 1').first()
        clustername_v = cluster_v[0]
        cname_v = cluster_v[1]
        status_v = cluster_v[2]

        # query for vizag unit 3
        adm_viz3 = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.wardname,
                            models.Patient_data.department,
                            models.Patient_data.adate,
                            models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Vizag Unit 3',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_viz3 = db.query(models.Admission.plan).where(models.Admission.date == da, models.Admission.branch == 'Vizag Unit 3').first()
        mtd_viz3 = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.consultant,
                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.branch == 'Vizag Unit 3',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_viz3 = plan_viz3.plan
        try:
            Ach_p_viz3 = round((adm_viz3 / plan_viz3) * 100, 2)
        except ZeroDivisionError:
            Ach_p_viz3=0
        gap_viz3 = adm_viz3 - plan_viz3

        cluster_viz3 = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Vizag Unit 3').first()
        clustername_viz3 = cluster_viz3[0]
        cname_viz3 = cluster_viz3[1]
        status_viz3 = cluster_viz3[2]

        # query for Madhapur branch
        adm_m = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.wardname,
                         models.Patient_data.department,
                         models.Patient_data.adate,
                         models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Madhapur',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_m = db.query(models.Admission.plan).where(models.Admission.date == da, models.Admission.branch == 'Madhapur').first()
        mtd_m = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.consultant,
                         models.Patient_data.department,
                         models.Patient_data.wardname,
                         models.Patient_data.branch,
                         models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Madhapur',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_m = plan_m.plan
        try:
            Ach_p_m = round((adm_m / plan_m) * 100, 2)
        except ZeroDivisionError:
            Ach_p_m=0
        gap_m = adm_m - plan_m

        cluster_m = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Madhapur').first()
        clustername_m = cluster_m[0]
        cname_m = cluster_m[1]
        status_m = cluster_m[2]

        # query for Karimnagar branch
        adm_karim = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.wardname,
                             models.Patient_data.department,
                             models.Patient_data.adate,
                             models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Karimnagar',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_karim = db.query(models.Admission.plan).where(models.Admission.date == da,models.Admission.branch == 'Karimnagar').first()
        mtd_karim = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.consultant,
                             models.Patient_data.department,
                             models.Patient_data.wardname,
                             models.Patient_data.branch,
                             models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Karimnagar',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_karim = plan_karim.plan
        try:
            Ach_p_karim = round((adm_m / plan_m) * 100, 2)
        except ZeroDivisionError:
            Ach_p_karim=0
        gap_karim = adm_m - plan_m

        cluster_karim = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Karimnagar').first()
        clustername_karim = cluster_karim[0]
        cname_karim = cluster_karim[1]
        status_karim = cluster_karim[2]

        # query for Nashik branch
        adm_nash = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.wardname,
                            models.Patient_data.department,
                            models.Patient_data.adate,
                            models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Nashik',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_nash = db.query(models.Admission.plan).where(models.Admission.date == da,models.Admission.branch == 'Nashik').first()
        mtd_nash = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.consultant,
                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Nashik',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_nash = plan_nash.plan
        try:
            Ach_p_nash = round((adm_nash / plan_nash) * 100, 2)
        except ZeroDivisionError:
            Ach_p_nash=0
        gap_nash = adm_nash - plan_nash

        cluster_nash = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Nashik').first()
        clustername_nash = cluster_nash[0]
        cname_nash = cluster_nash[1]
        status_nash = cluster_nash[2]

        # query for Nizamabad branch
        adm_niza = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.wardname,
                            models.Patient_data.department,
                            models.Patient_data.adate,
                            models.Patient_data.branch)\
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Nizamabad',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_niza = db.query(models.Admission.plan).where(models.Admission.date == da, models.Admission.branch == 'Nizamabad').first()
        mtd_niza = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.consultant,
                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Nizamabad',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_niza = plan_niza.plan
        try:
            Ach_p_niza = round((adm_niza / plan_niza) * 100, 2)
        except ZeroDivisionError:
            Ach_p_niza=0
        gap_niza = adm_niza - plan_niza

        cluster_niza = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Nellore').first()
        clustername_niza = cluster_niza[0]
        cname_niza = cluster_niza[1]
        status_niza = cluster_niza[2]

        # query for Nellore branch
        adm_nello = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.wardname,
                             models.Patient_data.department,
                             models.Patient_data.adate,
                             models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Nellore',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_nello = db.query(models.Admission.plan).where(models.Admission.date == da,models.Admission.branch == 'Nellore').first()
        mtd_nello = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.consultant,
                             models.Patient_data.department,
                             models.Patient_data.wardname,
                             models.Patient_data.branch,
                             models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Nellore',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_nello = plan_nello.plan
        try:
            Ach_p_nello = round((adm_nello / plan_nello) * 100, 2)
        except ZeroDivisionError:
            Ach_p_nello=0
        gap_nello = adm_nello - plan_nello

        cluster_nello = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Nellore').first()
        clustername_nello = cluster_nello[0]
        cname_nello = cluster_nello[1]
        status_nello = cluster_nello[2]

        # query for vizag unit 4
        adm_viz_u_4 = db.query(models.Patient_data.admntype,
                               models.Patient_data.ipno,
                               models.Patient_data.isbilldone,
                               models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Vizag Unit 4',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.admntype != 'D').count()

        plan_viz_u_4 = db.query(models.Admission.plan).where(models.Admission.date == da,models.Admission.branch == 'Vizag Unit 4').first()

        mtd_viz_u_4 = db.query(models.Patient_data.admntype,
                               models.Patient_data.ipno,
                               models.Patient_data.isbilldone,
                               models.Patient_data.branch,
                               models.Patient_data.adate)\
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Vizag Unit 4',
                   models.Patient_data.admntype != 'D',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_viz_u_4 = plan_viz_u_4.plan
        try:
            Ach_p_viz_u_4 = round((adm_viz_u_4 / plan_viz_u_4) * 100, 2)
        except ZeroDivisionError:
            Ach_p_viz_u_4=0
        gap_viz_u_4 = adm_viz_u_4 - plan_viz_u_4
        cluster_viz_u_4 = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Vizag Unit 4').first()
        clustername_viz_u_4 = cluster_viz_u_4[0]
        cname_viz_u_4 = cluster_viz_u_4[1]
        status_viz_u_4 = cluster_viz_u_4[2]

        # query for Aurangabad branch
        adm_aur = db.query(models.Patient_data.admntype,
                           models.Patient_data.ipno,
                           models.Patient_data.isbilldone,
                           models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Aurangabad',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.admntype != 'D').count()

        plan_aur = db.query(models.Admission.plan).where(models.Admission.date == da,models.Admission.branch == 'Aurangabad').first()

        mtd_aur = db.query(models.Patient_data.organization,
                           models.Patient_data.ipno,
                           models.Patient_data.isbilldone,
                           models.Patient_data.consultant,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.branch,
                           models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Aurangabad',

                   models.Patient_data.admntype != 'D',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_aur = plan_aur.plan
        try:
            Ach_p_aur = round((adm_aur / plan_aur) * 100, 2)
        except ZeroDivisionError:
            Ach_p_aur=0
        gap_aur = adm_aur - plan_aur
        cluastrer_aur = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Aurangabad').first()
        clustername_aur = cluastrer_aur[0]
        cname_aur = cluastrer_aur[1]
        status_aur = cluastrer_aur[2]

        # query for Sangamner branch
        adm_sang = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.wardname,
                            models.Patient_data.adate,
                            models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Sangamner',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS WARD').count()

        plan_sang = db.query(models.Admission.plan).where(models.Admission.date == da,models.Admission.branch == 'Sangamner').first()
        mtd_sang = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.consultant,
                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Sangamner',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.wardname != 'DIALYSIS WARD',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        plan_sang = plan_sang.plan
        try:
            Ach_p_sang = round((adm_sang / plan_sang) * 100, 2)
        except ZeroDivisionError:
            Ach_p_sang=0
        gap_sang = adm_sang - plan_sang

        cluster_sang = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(models.admission_dummy.branch == 'Sangamner').first()
        clustername_sang = cluster_sang[0]
        cname_sang = cluster_sang[1]
        status_sang = cluster_sang[2]

        # query for Kakinada branch
        adm_kaki = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.wardname,
                            models.Patient_data.department,
                            models.Patient_data.adate,
                            models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Kakinada',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_kaki = db.query(models.Admission.plan).where(models.Admission.date == da,models.Admission.branch == 'Kakinada').first()

        mtd_kaki = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,

                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Kakinada',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        plan_kaki = plan_kaki.plan
        try:
            Ach_p_kaki = round((adm_kaki / plan_kaki) * 100, 2)
        except ZeroDivisionError:
            Ach_p_kaki=0
        gap_kaki = adm_kaki - plan_kaki

        cluster_kaki = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(models.admission_dummy.branch == 'Kakinada').first()
        clustername_kaki = cluster_kaki[0]
        cname_kaki = cluster_kaki[1]
        status_kaki = cluster_kaki[2]

        # query for Mci branch
        adm_mci = db.query(models.Patient_data.organization,
                           models.Patient_data.ipno,
                           models.Patient_data.isbilldone,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.adate,
                           models.Patient_data.branch) \
            .where(models.Patient_data.adate == da,
                   models.Patient_data.branch == 'Mci',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.wardname != 'DIALY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.department != 'RADIATION ONCOLOGY').count()

        plan_mci = db.query(models.Admission.plan).where(models.Admission.date == da, models.Admission.branch == 'Mci').first()

        mtd_mci = db.query(models.Patient_data.organization,
                           models.Patient_data.ipno,
                           models.Patient_data.isbilldone,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.branch,
                           models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Mci',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.wardname != 'DIALY',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_mci = plan_mci.plan
        try:
            Ach_p_mci = round((adm_mci / plan_mci) * 100, 2)
        except ZeroDivisionError:
            Ach_p_mci=0
        gap_mci = adm_mci - plan_mci

        cluster_mci = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(models.admission_dummy.branch == 'Mci').first()
        clustername_mci = cluster_mci[0]
        cname_mci = cluster_mci[1]
        status_mci = cluster_mci[2]

        # query for begumpet
        adm_begum = db.query(models.Patient_data.organization,
                                 models.Patient_data.ipno,
                                 models.Patient_data.isbilldone,
                                 models.Patient_data.wardname,
                                 models.Patient_data.adate,
                                 models.Patient_data.branch) \
                .where(models.Patient_data.adate == date_one,
                       models.Patient_data.branch == 'Begumpet',
                       models.Patient_data.organization != 'Medicover Associate',
                       models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                       models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                       models.Patient_data.isbilldone != 'Hold',
                       models.Patient_data.isbilldone != 'Canceled',
                       models.Patient_data.wardname != 'DIALYSIS WARD').count()

        plan_begum = 60
        ach_p_begum = round((adm_begum / plan_begum) * 100, 2)
        gap_begum = adm_begum - plan_begum
        mtd_begum = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.consultant,
                             models.Patient_data.department,
                             models.Patient_data.wardname,
                             models.Patient_data.branch,
                             models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'Begumpet',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.wardname != 'DIALY',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        clustername_begum = 'Megha'
        cname_begum = 'ROTA'
        status_begum = 'Active'

        # query for navimumbai
        adm_navim = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.wardname,
                             models.Patient_data.adate,
                             models.Patient_data.branch) \
            .where(models.Patient_data.adate == date_one,
                   models.Patient_data.branch == 'NaviMumbai',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS WARD').count()

        plan_navim = 60
        ach_p_navim = round((adm_navim / plan_navim) * 100, 2)
        gap_navim = adm_navim - plan_navim
        mtd_navim = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.consultant,
                             models.Patient_data.department,
                             models.Patient_data.wardname,
                             models.Patient_data.branch,
                             models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, mtd_dat),
                   models.Patient_data.branch == 'NaviMumbai',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.wardname != 'DIALY',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        clustername_navim = 'Sachin'
        cname_navim = 'Maharastra'
        status_navim = 'Active'


        if branch == 'Sangareddy':
           return ({"branch":branch,"date":date_one,"admission": adm_san, "Achieved_p": Ach_p_san, "gap": gap_san, "plan": plan_san, "mtd": mtd_san,"clustername": clustername_san, "cname": cname_san, "status": status_san})

        if branch == 'Kurnool':
           return ({"branch":branch,"date":date_one,"admission": adm_k, "Achieved_p": Ach_p_k, "gap": gap_k, "plan": plan_k, "mtd": mtd_k,"clustername": clustername_k, "cname": cname_k, "status": status_k})

        if branch == 'Vizag Unit 1':
           return ({"branch":branch,"date":date_one,"admission": adm_v, "Achieved_p": Ach_p_v, "gap": gap_v, "plan": plan_v, "mtd": mtd_v,"clustername": clustername_v, "cname": cname_v, "status": status_v})

        if branch == 'Vizag Unit 3':
           return ({"branch":branch,"date":date_one,"admission": adm_viz3, "Achieved_p": Ach_p_viz3, "gap": gap_viz3, "plan": plan_viz3, "mtd": mtd_viz3,"clustername": clustername_viz3, "cname": cname_viz3, "status": status_viz3})

        if branch == 'Madhapur':
           return ({"branch":branch,"date":date_one,"admission": adm_m, "Achieved_p": Ach_p_m, "gap": gap_m, "plan": plan_m, "mtd": mtd_m,"clustername": clustername_m, "cname": cname_m, "status": status_m})

        if branch == 'Karimnagar':
           return ({"branch":branch,"date":date_one,"admission": adm_karim, "Achieved_p": Ach_p_karim, "gap": gap_karim, "plan": plan_karim, "mtd": mtd_karim,"clustername": clustername_karim, "cname": cname_karim, "status": status_karim})

        if branch == 'Nashik':
           return ({"branch":branch,"date":date_one,"admission": adm_nash, "Achieved_p": Ach_p_nash, "gap": gap_nash, "plan": plan_nash, "mtd": mtd_nash,"clustername": clustername_nash, "cname": cname_nash, "status": status_nash})

        if branch == 'Nizamabad':
           return ({"branch":branch,"date":date_one,"admission": adm_niza, "Achieved_p": Ach_p_niza, "gap": gap_niza, "plan": plan_niza, "mtd": mtd_niza,"clustername": clustername_niza, "cname": cname_niza, "status": status_niza})

        if branch == 'Nellore':
           return ({"branch":branch,"date":date_one,"admission": adm_nello, "Achieved_p": Ach_p_nello, "gap": gap_nello, "plan": plan_nello, "mtd": mtd_nello,"clustername": clustername_nello, "cname": cname_nello, "status": status_nello})

        if branch == 'Vizag Unit 4':
           return ({"branch":branch,"date":date_one,"admission": adm_viz_u_4, "Achieved_p": Ach_p_viz_u_4, "gap": gap_viz_u_4, "plan": plan_viz_u_4,"mtd": mtd_viz_u_4, "clustername": clustername_viz_u_4, "cname": cname_viz_u_4,"status": status_viz_u_4})

        if branch == 'Aurangabad':
           return ({"branch":branch,"date":date_one,"admission": adm_aur, "Achieved_p": Ach_p_aur, "gap": gap_aur, "plan": plan_aur, "mtd": mtd_aur,"clustername": clustername_aur, "cname": cname_aur, "status": status_aur})

        if branch == 'Sangamner':
           return ({"branch":branch,"date":date_one,"admission": adm_sang, "Achieved_p": Ach_p_sang, "gap": gap_sang, "plan": plan_sang, "mtd": mtd_sang,"clustername": clustername_sang, "cname": cname_sang, "status": status_sang})

        if branch == 'Kakinada':
           return ({"branch":branch,"date":date_one,"admission": adm_kaki, "Achieved_p": Ach_p_kaki, "gap": gap_kaki, "plan": plan_kaki, "mtd": mtd_kaki,"clustername": clustername_kaki, "cname": cname_kaki, "status": status_kaki})

        if branch == 'Mci':
           return ({"branch":branch,"date":date_one,"admission": adm_mci, "Achieved_p": Ach_p_mci, "gap": gap_mci, "plan": plan_mci, "mtd": mtd_mci,"clustername": clustername_mci, "cname": cname_mci, "status": status_mci})

        if branch=='Begumpet':
            return {"branch":branch,"date": date_one, "adm": adm_begum, "Achieved_p": ach_p_begum, "plan": plan_begum, "gap": gap_begum,"mtd": mtd_begum, "clustername": clustername_begum, "cname": cname_begum, "status": status_begum}

        if branch=='NaviMumbai':
            return {"branch":branch,"date": date_one, "adm": adm_navim, "Achieved_p": ach_p_navim, "plan": plan_navim, "gap": gap_navim,"mtd": mtd_navim, "clustername": clustername_navim, "cname": cname_navim, "status": status_navim}

        else:
          return {"error": "Invalid branch"}

@app.get('/')
def query(branch:str, db:Session=Depends(get_db)):
    q = db.query(models.admission_dummy.clustername,
                 models.admission_dummy.cname,models.admission_dummy.status)\
        .join(models.Patient_data,models.Patient_data.branch == models.admission_dummy.branch)\
        .filter(models.Patient_data.branch==branch).first()
    return q

@app.get('/q')
def que(branch:str, db:Session=Depends(get_db)):
    q1=db.query(models.admission_dummy.clustername,
                 models.admission_dummy.cname,
                 models.admission_dummy.status,
                 models.Patient_data.ipno,
                 models.Patient_data.consultant,
                 models.Patient_data.organization,
                 models.Patient_data.pname,
                 models.Admission.plan,
                 models.Admission.date)\
        .join(models.Patient_data,
              models.admission_dummy.branch==models.Patient_data.branch)\
        .join(models.Admission,models.admission_dummy.branch==models.Admission.branch)\
        .where(models.Patient_data.branch==branch) \
        .where(models.admission_dummy.branch==branch).first()

    return q1



@app.patch('/{sno}')
def update_user(sno, request: schema.Patient_data, db: Session = Depends(get_db)):
    user = db.query(models.Patient_data).filter(models.Patient_data.sno==sno)

    if not user.first():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f'The User with the sno {sno} is not found')

    user.update(request.dict(exclude={'createdAt'}, exclude_unset=True))

    db.commit()

    return user.first()
