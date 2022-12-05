
from fastapi import FastAPI, Depends, status, HTTPException
import tokn
import oauth
import hashing
from database import engine, SessionLocal
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



def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
models.Base.metadata.create_all(bind=engine)

pwd_cxt = CryptContext(schemes=["bcrypt"], deprecated="auto")



@app.post('/user', tags=['Userlogin'])
def create_user(request: schema.User, db:Session=Depends(get_db)):

    new_user= models.User(name=request.name, email=request.email, password=hashing.Hash.bcrypt(request.password))

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


# user authentication
@app.post("/token", tags=['Authentication'])
async def login_access(request:OAuth2PasswordRequestForm = Depends(),db:Session=Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == request.username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incorrect username or password")

    if not hashing.Hash.verify(user.password, request.password):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incorrect  password")

    access_token = tokn.create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}






@app.get('/All', tags=['admission api'])
def read_all(date:str,  db:Session=Depends(get_db), current_user: schema.User=Depends(oauth.get_current_user)):
    for format in ["%Y-%m-%d", "%Y/%m/%d", "%Y.%m.%d", "%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y", "%m/%d/%Y", "%m-%d-%Y",
                   "%m.%d.%Y"]:
        try:
            da = datetime.strptime(date, format).date()
            date_m= datetime.strptime(date, format).month


        except ValueError:
            pass
    for format in ['%Y-%m-%d', '%Y/%m/%d', '%Y.%m.%d', '%d/%m/%Y', '%d-%m-%Y', '%d.%m.%Y', '%m/%d/%Y', '%m-%d-%Y',
                   '%m.%d.%Y']:
        date_str = "2022-08-12"
        try:
            dat = datetime.strptime(date_str, format).date()
        except ValueError:
            pass

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
               models.Patient_data.organization != "Medicover Associate",
               models.Patient_data.organization != 'MEDICOVER HOSPITAL',
               models.Patient_data.organization != 'MEDICOVER CONSULTANT',
               models.Patient_data.department != 'GENERAL SURGERY',
               models.Patient_data.consultant != 'K.SRIDHAR',
               models.Patient_data.wardname != 'DIALYSIS WARD',
               models.Patient_data.isbilldone != 'Hold',
               models.Patient_data.isbilldone != 'Canceled').count()
    plan_san = db.query(models.Admission.plan).where(models.Admission.date == date,models.Admission.branch == 'Sangareddy').first()

    mtd_san = db.query(models.Patient_data.adate,
                       models.Patient_data.branch,
                       models.Patient_data.ipno,
                       models.Patient_data.organization,
                       models.Patient_data.department,
                       models.Patient_data.wardname,
                       models.Patient_data.consultant,
                       models.Patient_data.isbilldone) \
        .where(models.Patient_data.adate.between(da,dat),
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
    print(plan_san)
    Ach_p_san= round((adm_san / plan_san) * 100, 2)
    gap_san = adm_san- plan_san
    cluster_san = db.query(models.admission_dummy.clustername,models.admission_dummy.cname,models.admission_dummy.status).filter(models.admission_dummy.branch == 'Sangareddy').first()
    clustername_san = cluster_san[0]
    cname_san = cluster_san[1]
    status_san = cluster_san[2]

    # query for Kurnool branch
    adm_k= db.query(models.Patient_data.organization,
                     models.Patient_data.ipno,
                     models.Patient_data.isbilldone,
                     models.Patient_data.consultant,
                     models.Patient_data.department,
                     models.Patient_data.wardname,
                     models.Patient_data.branch,
                     models.Patient_data.adate)\
        .where(models.Patient_data.adate==da,
               models.Patient_data.branch == 'Kurnool',
               models.Patient_data.organization != "Medicover Associate",
               models.Patient_data.organization != 'MEDICOVER HOSPITAL',
               models.Patient_data.organization != 'MEDICOVER CONSULTANT',
               models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
               models.Patient_data.department != 'NEPHROLOGY',
               models.Patient_data.wardname != 'DAY CARE',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.isbilldone != 'Hold').count()


    plan_k=db.query(models.Admission.plan).where(models.Admission.date==date,models.Admission.branch=='Kurnool').first()

    mtd_k = db.query(models.Patient_data.organization,
                      models.Patient_data.ipno,
                      models.Patient_data.isbilldone,
                      models.Patient_data.consultant,
                      models.Patient_data.department,
                      models.Patient_data.wardname,
                      models.Patient_data.branch,
                      models.Patient_data.adate) \
        .where(models.Patient_data.adate.between(da, dat),
               models.Patient_data.branch == 'Kurnool',
               models.Patient_data.organization != "Medicover Associate",
               models.Patient_data.organization != 'MEDICOVER HOSPITAL',
               models.Patient_data.organization != 'MEDICOVER CONSULTANT',
               models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
               models.Patient_data.wardname != 'DAY CARE',
               models.Patient_data.department != 'NEPHROLOGY',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.isbilldone != 'Hold').count()

    plan_k=plan_k.plan
    Ach_p_k = round((adm_k/ plan_k) * 100, 2)
    gap_k= adm_k-plan_k
    cluster_k = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(models.admission_dummy.branch == 'kurnool').first()
    clustername_k = cluster_k[0]
    cname_k = cluster_k[1]
    status_k= cluster_k[2]

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

    plan_v = db.query(models.Admission.plan).where(models.Admission.date == date, models.Admission.branch == 'Vizag Unit 1').first()

    mtd_v = db.query(models.Patient_data.organization,
                      models.Patient_data.ipno,
                      models.Patient_data.isbilldone,
                      models.Patient_data.consultant,
                      models.Patient_data.department,
                      models.Patient_data.wardname,
                      models.Patient_data.branch,
                      models.Patient_data.adate) \
        .where(models.Patient_data.adate.between(da, dat),
               models.Patient_data.branch == 'Vizag Unit 1',
               models.Patient_data.organization != 'Medicover Associate',
               models.Patient_data.organization != 'MEDICOVER HOSPITAL',
               models.Patient_data.organization != 'MEDICOVER CONSULTANT',
               models.Patient_data.wardname != 'CRADLE WARD',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.isbilldone != 'Hold').count()

    plan_v = plan_v.plan
    Ach_p_v = round((adm_v / plan_v) * 100, 2)
    gap_v = adm_v - plan_v
    cluster_v = db.query(models.admission_dummy.clustername, models.admission_dummy.cname, models.admission_dummy.status).filter(models.admission_dummy.branch == 'Vizag Unit 1').first()
    clustername_v = cluster_v[0]
    cname_v = cluster_v[1]
    status_v = cluster_v[2]

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

    plan_m = db.query(models.Admission.plan).where(models.Admission.date == date,models.Admission.branch == 'Madhapur').first()
    mtd_m = db.query(models.Patient_data.organization,
                      models.Patient_data.ipno,
                      models.Patient_data.isbilldone,
                      models.Patient_data.consultant,
                      models.Patient_data.department,
                      models.Patient_data.wardname,
                      models.Patient_data.branch,
                      models.Patient_data.adate) \
        .where(models.Patient_data.adate.between(da, dat),
               models.Patient_data.organization != 'Medicover Associate',
               models.Patient_data.organization != 'MEDICOVER HOSPITAL',
               models.Patient_data.organization != 'MEDICOVER CONSULTANT',
               models.Patient_data.branch == 'Madhapur',
               models.Patient_data.department != 'NEPHROLOGY',
               models.Patient_data.wardname != 'DIALYSIS',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.isbilldone != 'Hold').count()

    plan_m = plan_m.plan
    Ach_p_m = round((adm_m / plan_m) * 100, 2)
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

    plan_karim = db.query(models.Admission.plan).where(models.Admission.date == date,models.Admission.branch == 'Karimnagar').first()
    mtd_karim = db.query(models.Patient_data.organization,
                     models.Patient_data.ipno,
                     models.Patient_data.isbilldone,
                     models.Patient_data.consultant,
                     models.Patient_data.department,
                     models.Patient_data.wardname,
                     models.Patient_data.branch,
                     models.Patient_data.adate) \
        .where(models.Patient_data.adate.between(da, dat),
               models.Patient_data.organization != 'Medicover Associate',
               models.Patient_data.organization != 'MEDICOVER HOSPITAL',
               models.Patient_data.organization != 'MEDICOVER CONSULTANT',
               models.Patient_data.branch == 'Karimnagar',
               models.Patient_data.department != 'NEPHROLOGY',
               models.Patient_data.wardname != 'DIALYSIS',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.isbilldone != 'Hold').count()

    plan_karim = plan_karim.plan
    Ach_p_karim= round((adm_m / plan_m) * 100, 2)
    gap_karim = adm_m - plan_m

    cluster_karim = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,models.admission_dummy.status).filter(models.admission_dummy.branch == 'Karimnagar').first()
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
        .where(models.Patient_data.adate == date,
               models.Patient_data.branch == 'Nashik',
               models.Patient_data.organization != 'Medicover Associate',
               models.Patient_data.organization != 'MEDICOVER HOSPITAL',
               models.Patient_data.organization != 'MEDICOVER CONSULTANT',
               models.Patient_data.department != 'NEPHROLOGY',
               models.Patient_data.isbilldone != 'Hold',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.wardname != 'DIALYSIS').count()

    plan_nash = db.query(models.Admission.plan).where(models.Admission.date == date, models.Admission.branch == 'Nashik').first()
    mtd_nash = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.department,
                         models.Patient_data.wardname,
                         models.Patient_data.branch,
                         models.Patient_data.adate) \
        .where(models.Patient_data.adate.between(da, dat),
               models.Patient_data.organization != 'Medicover Associate',
               models.Patient_data.organization != 'MEDICOVER HOSPITAL',
               models.Patient_data.organization != 'MEDICOVER CONSULTANT',
               models.Patient_data.branch == 'Nashik',
               models.Patient_data.department != 'NEPHROLOGY',
               models.Patient_data.wardname != 'DIALYSIS',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.isbilldone != 'Hold').count()

    plan_nash = plan_nash.plan
    Ach_p_nash= round((adm_nash / plan_nash) * 100, 2)
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
        .where(models.Patient_data.adate == date,
               models.Patient_data.branch == 'Nizamabad',
               models.Patient_data.organization != 'Medicover Associate',
               models.Patient_data.organization != 'MEDICOVER HOSPITAL',
               models.Patient_data.organization != 'MEDICOVER CONSULTANT',
               models.Patient_data.department != 'NEPHROLOGY',
               models.Patient_data.isbilldone != 'Hold',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.wardname != 'DIALYSIS').count()

    plan_niza = db.query(models.Admission.plan).where(models.Admission.date == date, models.Admission.branch == 'Nizamabad').first()
    mtd_niza = db.query(models.Patient_data.organization,
                        models.Patient_data.ipno,
                        models.Patient_data.isbilldone,
                        models.Patient_data.department,
                        models.Patient_data.wardname,
                        models.Patient_data.branch,
                        models.Patient_data.adate) \
        .where(models.Patient_data.adate.between(da, dat),
               models.Patient_data.branch == 'Nizamabad',
               models.Patient_data.organization != 'Medicover Associate',
               models.Patient_data.organization != 'MEDICOVER HOSPITAL',
               models.Patient_data.organization != 'MEDICOVER CONSULTANT',
               models.Patient_data.department != 'NEPHROLOGY',
               models.Patient_data.wardname != 'DIALYSIS',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.isbilldone != 'Hold').count()

    plan_niza = plan_niza.plan
    Ach_p_niza = round((adm_niza/ plan_niza) * 100, 2)
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
        .where(models.Patient_data.adate == date,
               models.Patient_data.branch == 'Nellore',
               models.Patient_data.organization != 'Medicover Associate',
               models.Patient_data.organization != 'MEDICOVER HOSPITAL',
               models.Patient_data.organization != 'MEDICOVER CONSULTANT',
               models.Patient_data.department != 'NEPHROLOGY',
               models.Patient_data.isbilldone != 'Hold',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.wardname != 'DIALYSIS').count()

    plan_nello = db.query(models.Admission.plan).where(models.Admission.date == date, models.Admission.branch == 'Nellore').first()
    mtd_nello = db.query(models.Patient_data.organization,
                        models.Patient_data.ipno,
                        models.Patient_data.isbilldone,
                        models.Patient_data.consultant,
                        models.Patient_data.department,
                        models.Patient_data.wardname,
                        models.Patient_data.branch,
                        models.Patient_data.adate) \
        .where(models.Patient_data.adate.between(da, dat),
               models.Patient_data.branch == 'Nellore',
               models.Patient_data.organization != 'Medicover Associate',
               models.Patient_data.organization != 'MEDICOVER HOSPITAL',
               models.Patient_data.organization != 'MEDICOVER CONSULTANT',
               models.Patient_data.department != 'NEPHROLOGY',
               models.Patient_data.wardname != 'DIALYSIS',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.isbilldone != 'Hold').count()

    plan_nello = plan_nello.plan
    Ach_p_nello = round((adm_nello / plan_nello) * 100, 2)
    gap_nello = adm_nello - plan_nello

    cluster_nello = db.query(models.admission_dummy.clustername, models.admission_dummy.cname, models.admission_dummy.status).filter(
        models.admission_dummy.branch == 'Nellore').first()
    clustername_nello = cluster_nello[0]
    cname_nello = cluster_nello[1]
    status_nello = cluster_nello[2]

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

    plan_aur = db.query(models.Admission.plan).where(models.Admission.date == date,
                                                   models.Admission.branch == 'Aurangabad').first()

    mtd_aur = db.query(models.Patient_data.admntype,
                      models.Patient_data.ipno,
                      models.Patient_data.isbilldone,
                      models.Patient_data.branch,
                      models.Patient_data.adate) \
        .where(models.Patient_data.adate.between(da, dat),
               models.Patient_data.branch == 'Aurangabad',

               models.Patient_data.admntype != 'D',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.isbilldone != 'Hold').count()

    plan_aur = plan_aur.plan
    Ach_p_aur = round((adm_aur / plan_aur) * 100, 2)
    gap_aur = adm_aur - plan_aur
    cluastrer_aur = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                      models.admission_dummy.status).filter(models.admission_dummy.branch == 'Aurangabad').first()
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
        .where(models.Patient_data.adate == date,
               models.Patient_data.branch == 'Sangamner',
               models.Patient_data.organization != 'Medicover Associate',
               models.Patient_data.organization != 'MEDICOVER HOSPITAL',
               models.Patient_data.organization != 'MEDICOVER CONSULTANT',
               models.Patient_data.isbilldone != 'Hold',
               models.Patient_data.isbilldone != 'Canceled',

               models.Patient_data.wardname != 'DIALYSIS WARD').count()

    plan_sang = db.query(models.Admission.plan).where(models.Admission.date == date,
                                                   models.Admission.branch == 'Sangamner').first()
    mtd_sang = db.query(models.Patient_data.organization,
                      models.Patient_data.ipno,
                      models.Patient_data.isbilldone,
                      models.Patient_data.consultant,
                      models.Patient_data.department,
                      models.Patient_data.wardname,
                      models.Patient_data.branch,
                      models.Patient_data.adate) \
        .where(models.Patient_data.adate.between(da, dat),
               models.Patient_data.branch == 'Sangamner',
               models.Patient_data.organization != 'Medicover Associate',
               models.Patient_data.organization != 'MEDICOVER HOSPITAL',
               models.Patient_data.organization != 'MEDICOVER CONSULTANT',
               models.Patient_data.wardname != 'DIALYSIS WARD',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.isbilldone != 'Hold').count()
    plan_sang = plan_sang.plan
    Ach_p_sang = round((adm_sang / plan_sang) * 100, 2)
    gap_sang = adm_sang - plan_sang

    cluster_sang = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                      models.admission_dummy.status).filter(models.admission_dummy.branch == 'Sangamner').first()
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

    plan_kaki = db.query(models.Admission.plan).where(models.Admission.date == date,
                                                   models.Admission.branch == 'Kakinada').first()

    mtd_kaki = db.query(models.Patient_data.organization,
                      models.Patient_data.ipno,
                      models.Patient_data.isbilldone,
                      models.Patient_data.consultant,
                      models.Patient_data.department,
                      models.Patient_data.wardname,
                      models.Patient_data.branch,
                      models.Patient_data.adate) \
        .where(models.Patient_data.adate.between(da, dat),
               models.Patient_data.branch == 'Kakinada',
               models.Patient_data.organization != 'Medicover Associate',
               models.Patient_data.organization != 'MEDICOVER HOSPITAL',
               models.Patient_data.organization != 'MEDICOVER CONSULTANT',
               models.Patient_data.department != 'RADIATION ONCOLOGY',
               models.Patient_data.wardname != 'DIALYSIS',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.isbilldone != 'Hold').count()
    plan_kaki = plan_kaki.plan
    Ach_p_kaki = round((adm_kaki / plan_kaki) * 100, 2)
    gap_kaki = adm_kaki - plan_kaki

    cluster_kaki = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                      models.admission_dummy.status).filter(models.admission_dummy.branch == 'Kakinada').first()
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

    plan_mci = db.query(models.Admission.plan).where(models.Admission.date == date,
                                                   models.Admission.branch == 'Mci').first()

    mtd_mci = db.query(models.Patient_data.organization,
                      models.Patient_data.ipno,
                      models.Patient_data.isbilldone,
                      models.Patient_data.consultant,
                      models.Patient_data.department,
                      models.Patient_data.wardname,
                      models.Patient_data.branch,
                      models.Patient_data.adate) \
        .where(models.Patient_data.adate.between(da, dat),
               models.Patient_data.branch == 'Mci',
               models.Patient_data.organization != 'Medicover Associate',
               models.Patient_data.organization != 'MEDICOVER HOSPITAL',
               models.Patient_data.organization != 'MEDICOVER CONSULTANT',
               models.Patient_data.department != 'RADIATION ONCOLOGY',
               models.Patient_data.wardname != 'DIALY',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.isbilldone != 'Hold').count()

    plan_mci = plan_mci.plan
    Ach_p_mci = round((adm_mci / plan_mci) * 100, 2)
    gap_mci = adm_mci - plan_mci

    cluster_mci = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                      models.admission_dummy.status).filter(models.admission_dummy.branch == 'Mci').first()
    clustername_mci = cluster_mci[0]
    cname_mci = cluster_mci[1]
    status_mci = cluster_mci[2]



    return ["Sangareddy",{"admission":adm_san,"Achieved_p":Ach_p_san, "gap":gap_san, "plan":plan_san, "mtd": mtd_san, "clustername": clustername_san, "cname":cname_san, "status":status_san}],["Kurnool",
            {"admission":adm_k, "Achieved_p":Ach_p_k, "gap":gap_k, "plan":plan_k, "mtd":mtd_k, "clustername": clustername_k, "cname":cname_k, "status":status_k}],["Vizag Unit1",
            {"admission":adm_v,"Achieved_p":Ach_p_v, "gap":gap_v, "plan":plan_v, "mtd": mtd_v, "clustername": clustername_v, "cname":cname_v, "status":status_v}],["Madhapur",
            {"admission":adm_m,"Achieved_p":Ach_p_m, "gap":gap_m, "plan":plan_m, "mtd": mtd_m, "clustername": clustername_m, "cname":cname_m, "status":status_m}],["karimnagar",
            {"admission":adm_karim,"Achieved_p":Ach_p_karim, "gap":gap_karim, "plan":plan_karim, "mtd": mtd_karim, "clustername": clustername_karim, "cname":cname_karim, "status":status_karim}],["Nashik",
            {"admission":adm_nash,"Achieved_p":Ach_p_nash, "gap":gap_nash, "plan":plan_nash, "mtd": mtd_nash, "clustername": clustername_nash, "cname":cname_nash, "status":status_nash}],["Nizamabad",
            {"admission":adm_niza,"Achieved_p":Ach_p_niza, "gap":gap_niza, "plan":plan_niza, "mtd": mtd_niza, "clustername": clustername_niza, "cname":cname_niza, "status":status_niza}],["Nellore",
            {"admission":adm_nello,"Achieved_p":Ach_p_nello, "gap":gap_nello, "plan":plan_nello, "mtd": mtd_nello, "clustername": clustername_nello, "cname":cname_nello, "status":status_nello}],["Aurangabad",
            {"admission":adm_aur,"Achieved_p":Ach_p_aur, "gap":gap_aur, "plan":plan_aur, "mtd": mtd_aur, "clustername": clustername_aur, "cname":cname_aur, "status":status_aur}],["Sangamner",
            {"admission":adm_sang,"Achieved_p":Ach_p_sang, "gap":gap_sang, "plan":plan_sang, "mtd": mtd_sang, "clustername": clustername_sang, "cname":cname_sang, "status":status_sang}],["Kakinada",
            {"admission":adm_kaki,"Achieved_p":Ach_p_kaki, "gap":gap_kaki, "plan":plan_kaki, "mtd": mtd_kaki, "clustername": clustername_kaki, "cname":cname_kaki, "status":status_kaki}],["Mci",
            {"admission":adm_mci,"Achieved_p":Ach_p_mci, "gap":gap_mci, "plan":plan_mci, "mtd": mtd_mci, "clustername": clustername_mci, "cname":cname_mci, "status":status_mci}]

@app.post('/read branch details', tags=['admission api'])
def read(date:str, branch:str, db:Session=Depends(get_db)):
    for format in ["%Y-%m-%d", "%Y/%m/%d", "%Y.%m.%d", "%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y", "%m/%d/%Y", "%m-%d-%Y",
                   "%m.%d.%Y"]:
        try:
            da = datetime.strptime(date, format).date()
            date_m= datetime.strptime(date, format).month


        except ValueError:
            pass
    for format in ['%Y-%m-%d', '%Y/%m/%d', '%Y.%m.%d', '%d/%m/%Y', '%d-%m-%Y', '%d.%m.%Y', '%m/%d/%Y', '%m-%d-%Y',
                   '%m.%d.%Y']:
        date_str = "2022-08-12"
        try:
            dat = datetime.strptime(date_str, format).date()
        except ValueError:
            pass

        # query for sangareddy branch
        adm_san = db.query(models.Patient_data.adate,
                           models.Patient_data.branch,
                           models.Patient_data.ipno,
                           models.Patient_data.organization,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.consultant,
                           models.Patient_data.isbilldone) \
            .where(models.Patient_data.adate == date,
                   models.Patient_data.branch == 'Sangareddy',
                   models.Patient_data.organization != "Medicover Associate%",
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'GENERAL SURGERY',
                   models.Patient_data.consultant != 'K.SRIDHAR',
                   models.Patient_data.wardname != 'DIALYSIS WARD',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled').count()
        plan_san = db.query(models.Admission.plan).where(models.Admission.date == date,
                                                         models.Admission.branch == 'Sangareddy').first()

        mtd_san = db.query(models.Patient_data.adate,
                           models.Patient_data.branch,
                           models.Patient_data.ipno,
                           models.Patient_data.organization,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.consultant,
                           models.Patient_data.isbilldone) \
            .where(models.Patient_data.adate.between(da, dat),
                   models.Patient_data.branch == 'Sangareddy',
                   models.Patient_data.organization != "Medicover Associate%",
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'GENERAL SURGERY',
                   models.Patient_data.consultant != 'K.SRIDHAR',
                   models.Patient_data.wardname != 'DIALYSIS WARD',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled').count()

        plan_san = plan_san.plan
        # print(plan_san)
        Ach_p_san = round((adm_san / plan_san) * 100, 2)
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
            .where(models.Patient_data.adate == date,
                   models.Patient_data.branch == 'Kurnool',
                   models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
                   models.Patient_data.wardname != 'DAY CARE',
                   models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DAY CARE',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_k = db.query(models.Admission.plan).where(models.Admission.date == date,
                                                       models.Admission.branch == 'Kurnool').first()

        mtd_k = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.consultant,
                         models.Patient_data.department,
                         models.Patient_data.wardname,
                         models.Patient_data.branch,
                         models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, dat),
                   models.Patient_data.branch == 'Kurnool',
                   models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
                   models.Patient_data.wardname != 'DAY CARE',
                   models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DAY CARE',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_k = plan_k.plan
        Ach_p_k = round((adm_k / plan_k) * 100, 2)
        gap_k = adm_k - plan_k
        cluster_k = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                             models.admission_dummy.status).filter(models.admission_dummy.branch == 'kurnool').first()
        clustername_k = cluster_k[0]
        cname_k = cluster_k[1]
        status_k = cluster_k[2]

        # query for Vizag Unit1 branch
        adm_v = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.wardname,
                         models.Patient_data.adate, models.Patient_data.branch) \
            .where(models.Patient_data.adate == date,
                   models.Patient_data.branch == 'Vizag Unit 1',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'CRADLE WARD').count()

        plan_v = db.query(models.Admission.plan).where(models.Admission.date == date,
                                                       models.Admission.branch == 'Vizag Unit 1').first()

        mtd_v = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.consultant,
                         models.Patient_data.department,
                         models.Patient_data.wardname,
                         models.Patient_data.branch,
                         models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, dat),
                   models.Patient_data.branch == 'Vizag Unit 1',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.wardname != 'CRADLE WARD',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_v = plan_v.plan
        Ach_p_v = round((adm_v / plan_v) * 100, 2)
        gap_v = adm_v - plan_v
        cluster_v = db.query(models.admission_dummy.clustername, models.admission_dummy.cname, models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Vizag Unit 1').first()
        clustername_v = cluster_v[0]
        cname_v = cluster_v[1]
        status_v = cluster_v[2]

        # query for Madhapur branch
        adm_m = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.wardname,
                         models.Patient_data.department,
                         models.Patient_data.adate,
                         models.Patient_data.branch) \
            .where(models.Patient_data.adate == date,
                   models.Patient_data.branch == 'Madhapur',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_m = db.query(models.Admission.plan).where(models.Admission.date == date,models.Admission.branch == 'Madhapur').first()
        mtd_m = db.query(models.Patient_data.organization,
                         models.Patient_data.ipno,
                         models.Patient_data.isbilldone,
                         models.Patient_data.consultant,
                         models.Patient_data.department,
                         models.Patient_data.wardname,
                         models.Patient_data.branch,
                         models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, dat),
                   models.Patient_data.branch == 'Madhapur',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_m = plan_m.plan
        Ach_p_m = round((adm_m / plan_m) * 100, 2)
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
            .where(models.Patient_data.adate == date,
                   models.Patient_data.branch == 'Karimnagar',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_karim = db.query(models.Admission.plan).where(models.Admission.date == date, models.Admission.branch == 'Karimnagar').first()
        mtd_karim = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.consultant,
                             models.Patient_data.department,
                             models.Patient_data.wardname,
                             models.Patient_data.branch,
                             models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, dat),
                   models.Patient_data.branch == 'Karimnagar',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_karim = plan_karim.plan
        Ach_p_karim = round((adm_m / plan_m) * 100, 2)
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
            .where(models.Patient_data.adate == date,
                   models.Patient_data.branch == 'Nashik',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_nash = db.query(models.Admission.plan).where(models.Admission.date == date,
                                                          models.Admission.branch == 'Nashik').first()
        mtd_nash = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.consultant,
                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, dat),
                   models.Patient_data.branch == 'Nashik',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_nash = plan_nash.plan
        Ach_p_nash = round((adm_nash / plan_nash) * 100, 2)
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
            .where(models.Patient_data.adate == date,
                   models.Patient_data.branch == 'Nizamabad',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_niza = db.query(models.Admission.plan).where(models.Admission.date == date,
                                                          models.Admission.branch == 'Nizamabad').first()
        mtd_niza = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.consultant,
                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, dat),
                   models.Patient_data.branch == 'Nizamabad',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_niza = plan_niza.plan
        Ach_p_niza = round((adm_niza / plan_niza) * 100, 2)
        gap_niza = adm_niza - plan_niza

        cluster_niza = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                                models.admission_dummy.status).filter(
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
            .where(models.Patient_data.adate == date,
                   models.Patient_data.branch == 'Nellore',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_nello = db.query(models.Admission.plan).where(models.Admission.date == date,
                                                           models.Admission.branch == 'Nellore').first()
        mtd_nello = db.query(models.Patient_data.organization,
                             models.Patient_data.ipno,
                             models.Patient_data.isbilldone,
                             models.Patient_data.consultant,
                             models.Patient_data.department,
                             models.Patient_data.wardname,
                             models.Patient_data.branch,
                             models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, dat),
                   models.Patient_data.branch == 'Nellore',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'NEPHROLOGY',
                   models.Patient_data.wardname != 'DIALYSIS',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_nello = plan_nello.plan
        Ach_p_nello = round((adm_nello / plan_nello) * 100, 2)
        gap_nello = adm_nello - plan_nello

        cluster_nello = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                                 models.admission_dummy.status).filter(
            models.admission_dummy.branch == 'Nellore').first()
        clustername_nello = cluster_nello[0]
        cname_nello = cluster_nello[1]
        status_nello = cluster_nello[2]

        # query for Aurangabad branch
        adm_aur = db.query(models.Patient_data.admntype,
                           models.Patient_data.ipno,
                           models.Patient_data.isbilldone,
                           models.Patient_data.branch) \
            .where(models.Patient_data.adate == date,
                   models.Patient_data.branch == 'Aurangabad',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.admntype != 'D').count()

        plan_aur = db.query(models.Admission.plan).where(models.Admission.date == date,
                                                         models.Admission.branch == 'Aurangabad').first()

        mtd_aur = db.query(models.Patient_data.organization,
                           models.Patient_data.ipno,
                           models.Patient_data.isbilldone,
                           models.Patient_data.consultant,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.branch,
                           models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, dat),
                   models.Patient_data.branch == 'Aurangabad',

                   models.Patient_data.admntype != 'D',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_aur = plan_aur.plan
        Ach_p_aur = round((adm_aur / plan_aur) * 100, 2)
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
            .where(models.Patient_data.adate == date,
                   models.Patient_data.branch == 'Sangamner',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS WARD').count()

        plan_sang = db.query(models.Admission.plan).where(models.Admission.date == date,
                                                          models.Admission.branch == 'Sangamner').first()
        mtd_sang = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,
                            models.Patient_data.consultant,
                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, dat),
                   models.Patient_data.branch == 'Sangamner',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.wardname != 'DIALYSIS WARD',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        plan_sang = plan_sang.plan
        Ach_p_sang = round((adm_sang / plan_sang) * 100, 2)
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
            .where(models.Patient_data.adate == date,
                   models.Patient_data.branch == 'Kakinada',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.isbilldone != 'Hold',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.wardname != 'DIALYSIS').count()

        plan_kaki = db.query(models.Admission.plan).where(models.Admission.date == date,
                                                          models.Admission.branch == 'Kakinada').first()

        mtd_kaki = db.query(models.Patient_data.organization,
                            models.Patient_data.ipno,
                            models.Patient_data.isbilldone,

                            models.Patient_data.department,
                            models.Patient_data.wardname,
                            models.Patient_data.branch,
                            models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, dat),
                   models.Patient_data.branch == 'Kakinada',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.wardname !='DIALYSIS',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()
        plan_kaki = plan_kaki.plan
        Ach_p_kaki = round((adm_kaki / plan_kaki) * 100, 2)
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

        plan_mci = db.query(models.Admission.plan).where(models.Admission.date == date,
                                                         models.Admission.branch == 'Mci').first()

        mtd_mci = db.query(models.Patient_data.organization,
                           models.Patient_data.ipno,
                           models.Patient_data.isbilldone,
                           models.Patient_data.department,
                           models.Patient_data.wardname,
                           models.Patient_data.branch,
                           models.Patient_data.adate) \
            .where(models.Patient_data.adate.between(da, dat),
                   models.Patient_data.branch == 'Mci',
                   models.Patient_data.organization != 'Medicover Associate',
                   models.Patient_data.organization != 'MEDICOVER HOSPITAL',
                   models.Patient_data.organization != 'MEDICOVER CONSULTANT',
                   models.Patient_data.department != 'RADIATION ONCOLOGY',
                   models.Patient_data.wardname != 'DIALY',
                   models.Patient_data.isbilldone != 'Canceled',
                   models.Patient_data.isbilldone != 'Hold').count()

        plan_mci = plan_mci.plan
        Ach_p_mci = round((adm_mci / plan_mci) * 100, 2)
        gap_mci = adm_mci - plan_mci

        cluster_mci = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                               models.admission_dummy.status).filter(models.admission_dummy.branch == 'Mci').first()
        clustername_mci = cluster_mci[0]
        cname_mci = cluster_mci[1]
        status_mci = cluster_mci[2]

    if branch=='Sangareddy':
        return ({"admission": adm_san, "Achieved_p": Ach_p_san, "gap": gap_san, "plan": plan_san, "mtd": mtd_san,"clustername": clustername_san, "cname": cname_san, "status": status_san})

    if branch=='Kurnool':
        return({"admission":adm_k, "Achieved_p":Ach_p_k, "gap":gap_k, "plan":plan_k, "mtd":mtd_k, "clustername": clustername_k, "cname":cname_k, "status":status_k})

    if branch== 'Vizag Unit 1':
        return({"admission":adm_v,"Achieved_p":Ach_p_v, "gap":gap_v, "plan":plan_v, "mtd": mtd_v, "clustername": clustername_v, "cname":cname_v, "status":status_v})

    if branch=='Madhapur':
        return({"admission":adm_m,"Achieved_p":Ach_p_m, "gap":gap_m, "plan":plan_m, "mtd": mtd_m, "clustername": clustername_m, "cname":cname_m, "status":status_m})

    if branch=='Karimnagar':
        return ({"admission":adm_karim,"Achieved_p":Ach_p_karim, "gap":gap_karim, "plan":plan_karim, "mtd": mtd_karim, "clustername": clustername_karim, "cname":cname_karim, "status":status_karim})

    if branch=='Nashik':
        return ({"admission":adm_nash,"Achieved_p":Ach_p_nash, "gap":gap_nash, "plan":plan_nash, "mtd": mtd_nash, "clustername": clustername_nash, "cname":cname_nash, "status":status_nash})

    if branch=='Nizamabad':
        return({"admission":adm_niza,"Achieved_p":Ach_p_niza, "gap":gap_niza, "plan":plan_niza, "mtd": mtd_niza, "clustername": clustername_niza, "cname":cname_niza, "status":status_niza})

    if branch=='Nellore':
        return ({"admission":adm_nello,"Achieved_p":Ach_p_nello, "gap":gap_nello, "plan":plan_nello, "mtd": mtd_nello, "clustername": clustername_nello, "cname":cname_nello, "status":status_nello})

    if branch=='Aurangabad':
        return ({"admission":adm_aur,"Achieved_p":Ach_p_aur, "gap":gap_aur, "plan":plan_aur, "mtd": mtd_aur, "clustername": clustername_aur, "cname":cname_aur, "status":status_aur})

    if branch=='Sangamner':
        return({"admission":adm_sang,"Achieved_p":Ach_p_sang, "gap":gap_sang, "plan":plan_sang, "mtd": mtd_sang, "clustername": clustername_sang, "cname":cname_sang, "status":status_sang})

    elif branch=='Kakinada':
        return({"admission":adm_kaki,"Achieved_p":Ach_p_kaki, "gap":gap_kaki, "plan":plan_kaki, "mtd": mtd_kaki, "clustername": clustername_kaki, "cname":cname_kaki, "status":status_kaki})

    elif branch=='Mci':
        return({"admission":adm_mci,"Achieved_p":Ach_p_mci, "gap":gap_mci, "plan":plan_mci, "mtd": mtd_mci, "clustername": clustername_mci, "cname":cname_mci, "status":status_mci})
    else:
        return{"error": "Invalid branch"}
