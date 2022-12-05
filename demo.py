from typing import Union, Optional

from fastapi import FastAPI, Depends
from sqlalchemy import select

from database import engine, SessionLocal
from sqlalchemy.orm import Session
import models
from models import *
from sqlalchemy import and_, or_, not_

from datetime import date, datetime

app=FastAPI()



def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
models.Base.metadata.create_all(bind=engine)



@app.post('/admissionplan')
def admission(date: str, branch: str, db: Session = Depends(get_db)):
    # data = '2022-08-01'
    # date_time_obj = datetime.strptime(data, "%Y-%m-%d")

    # result = db.query(Admission).filter_by(branch=branch,date=datetime.strptime(date,"%Y-%m-%d").date()).all()
    # plan = result[0].plan
    # return {"Branch":branch,"plan":plan}
    results = db.query(models.Admission.plan, models.Admission.branch, models.Admission.date).where(models.Admission.date ==date,models.Admission.branch == branch).first()
    return results



@app.post('/sangareddy')
def adm(date:str,branch:str,db:Session=Depends(get_db)):
    print(date, branch)

    for format in ["%Y-%m-%d", "%Y/%m/%d", "%Y.%m.%d", "%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y", "%m/%d/%Y", "%m-%d-%Y",
                   "%m.%d.%Y"]:
        try:
            data = datetime.strptime(date, format).date()
            print(data)
        except ValueError:
            pass


    result= db.query(models.Patient_data.adate,
                     models.Patient_data.branch,
                     models.Patient_data.ipno,
                     models.Patient_data.organization,
                     # models.Patient_data.department,
                     models.Patient_data.isbilldone).distinct()\
                .filter(models.Patient_data.adate==date,
                        models.Patient_data.branch==branch,
                        and_(models.Patient_data.organization.like("%Medicover Associate%")),
                        and_(models.Patient_data.organization.like('%MEDICOVER HOSPITAL%')),
                        and_(models.Patient_data.organization.like('%MEDICOVER CONSULTANT%')),
                        # and_(models.Patient_data.department.like('%GENERAL SURGERY%')),
                        not_(models.Patient_data.isbilldone.like('%Hold%')),
                        not_(models.Patient_data.isbilldone.like('%Canceled%')))\
                .count()-db.query(models.Patient_data.adate,
                                  models.Patient_data.ipno,
                                  models.Patient_data.branch,
                                  models.Patient_data.consultant,
                                  models.Patient_data.wardname,
                                  models.Patient_data.isbilldone).distinct()\
        .filter(models.Patient_data.adate==date,
                models.Patient_data.branch==branch,
                and_(models.Patient_data.consultant=='K.SRIDHAR'),
                and_(models.Patient_data.wardname=='DIALYSIS WARD'),
                not_(models.Patient_data.isbilldone.like('%Canceled%')),
                not_(models.Patient_data.isbilldone.like('%Hold%'))).count()

    result1= db.query(models.Admission.plan).where(models.Admission.date==date,models.Admission.branch==branch).first()
    result1=result1.plan
    print(result1)
    Ach=round((result/result1)*100,2)
    gap= result-result1
    query4= db.query(models.admission_dummy.clustername).filter(models.admission_dummy.branch==branch).first()

    return{"admission":result, "Achieved_p":Ach, "gap":gap, "plan":result1, "clustername":query4}


@app.post('/s')
def ad(db:Session=Depends(get_db)):
    res=db.execute("SELECT COUNT(`ipno`) AS adm, `patient_data`.`branch` AS Branch FROM `patient_data` where DATE(`adate`) = '2022-08-01' AND `patient_data`.`organization` NOT IN ('Medicover Associate','MEDICOVER HOSPITAL','MEDICOVER CONSULTANT') AND `patient_data`.`consultant` != 'K.SRIDHAR' AND `patient_data`.`department` != 'GENERAL SURGERY' AND `wardname` != 'DIALYSIS WARD' AND `branch` = 'Sangareddy' GROUP BY branch")
    return res



@app.post('/Kurnool')
def kurn(date:str, branch:str, db:Session=Depends(get_db)):
    for format in ["%Y-%m-%d", "%Y/%m/%d", "%Y.%m.%d", "%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y", "%m/%d/%Y", "%m-%d-%Y",
                   "%m.%d.%Y"]:
        try:
            da = datetime.strptime(date, format).date()
            date_m= datetime.strptime(date, format).month


        except ValueError:
            pass
    for format in ['%Y-%m-%d', '%Y/%m/%d', '%Y.%m.%d', '%d/%m/%Y', '%d-%m-%Y', '%d.%m.%Y', '%m/%d/%Y', '%m-%d-%Y',
                   '%m.%d.%Y']:
        date_str = "2022-08-01"
        try:
            dat = datetime.strptime(date_str, format).date()
        except ValueError:
            pass

    adm= db.query(models.Patient_data.organization,
                     models.Patient_data.ipno,
                     models.Patient_data.isbilldone,
                     models.Patient_data.consultant,
                     models.Patient_data.department,
                     models.Patient_data.wardname,
                     models.Patient_data.branch,
                     models.Patient_data.adate)\
        .where(models.Patient_data.adate==date,
               models.Patient_data.branch == branch,
               models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
               models.Patient_data.wardname != 'DAY CARE',
               models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
               models.Patient_data.department != 'NEPHROLOGY',
               models.Patient_data.wardname != 'DAY CARE',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.isbilldone != 'Hold').count()


    query2=db.query(models.Admission.plan).where(models.Admission.date==date,models.Admission.branch==branch).first()

    mtd = db.query(models.Patient_data.organization,
                      models.Patient_data.ipno,
                      models.Patient_data.isbilldone,
                      models.Patient_data.consultant,
                      models.Patient_data.department,
                      models.Patient_data.wardname,
                      models.Patient_data.branch,
                      models.Patient_data.adate) \
        .where(models.Patient_data.adate.between(dat, da),
               models.Patient_data.branch == branch,
               models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
               models.Patient_data.wardname != 'DAY CARE',
               models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
               models.Patient_data.department != 'NEPHROLOGY',
               models.Patient_data.wardname != 'DAY CARE',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.isbilldone != 'Hold').count()

    query=query2.plan
    Ach_p = round((adm / query) * 100, 2)
    gap= adm-query
    query4= db.query(models.admission_dummy.clustername, models.admission_dummy.cname, models.admission_dummy.status).filter(models.admission_dummy.branch==branch).first()
    clustername= query4[0]
    cname=query4[1]
    status=query4[2]

    print(dict(query4))
    # for x in x1:
    #     x.update(x.pop('clustername',{}))

    return {"admission":adm, "Achieved_p":Ach_p, "gap":gap, "plan":query, "mtd":mtd, "clustername": clustername, "cname":cname, "status":status}


@app.post('/Vizag Unit 1')
def vizag1(date:str, branch:str, db:Session=Depends(get_db)):

    for format in ["%Y-%m-%d", "%Y/%m/%d", "%Y.%m.%d", "%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y", "%m/%d/%Y", "%m-%d-%Y",
                   "%m.%d.%Y"]:
        try:
            da = datetime.strptime(date, format).date()
            date_m= datetime.strptime(date, format).month


        except ValueError:
            pass
    for format in ['%Y-%m-%d', '%Y/%m/%d', '%Y.%m.%d', '%d/%m/%Y', '%d-%m-%Y', '%d.%m.%Y', '%m/%d/%Y', '%m-%d-%Y',
                   '%m.%d.%Y']:
        date_str = "2022-08-02"
        try:
            dat = datetime.strptime(date_str, format).date()
        except ValueError:
            pass

    query1= db.query(models.Patient_data.organization,
                     models.Patient_data.ipno,
                     models.Patient_data.isbilldone,
                     models.Patient_data.wardname,
                     models.Patient_data.adate,models.Patient_data.branch)\
        .where(models.Patient_data.adate==date,
               models.Patient_data.branch==branch,
               models.Patient_data.organization!='Medicover Associate',
               models.Patient_data.organization!='MEDICOVER HOSPITAL',
               models.Patient_data.organization!='MEDICOVER CONSULTANT',
               models.Patient_data.isbilldone!='Hold',
               models.Patient_data.isbilldone!='Canceled',
               models.Patient_data.wardname!='CRADLE WARD').count()

    query2 = db.query(models.Admission.plan).where(models.Admission.date == date,
                                                   models.Admission.branch == branch).first()

    query3 = db.query(models.Patient_data.organization,
                      models.Patient_data.ipno,
                      models.Patient_data.isbilldone,
                      models.Patient_data.consultant,
                      models.Patient_data.department,
                      models.Patient_data.wardname,
                      models.Patient_data.branch,
                      models.Patient_data.adate) \
        .where(models.Patient_data.adate.between(dat, da),
               models.Patient_data.branch == branch,
               models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
               models.Patient_data.wardname != 'DAY CARE',
               models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
               models.Patient_data.department != 'NEPHROLOGY',
               models.Patient_data.wardname != 'DAY CARE',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.isbilldone != 'Hold').count()

    query = query2.plan
    Ach_p = round((query1 / query) * 100, 2)
    gap = query1 - query
    query4 = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                      models.admission_dummy.status).filter(models.admission_dummy.branch == branch).first()
    clustername = query4[0]
    cname = query4[1]
    status = query4[2]

    return {"admission":query1,"Achieved_p":Ach_p, "gap":gap, "plan":query, "mtd": query3, "clustername": clustername, "cname":cname, "status":status}

@app.post('/Vizag Unit 3')
def vizag3(date:str, branch:str, db:Session=Depends(get_db)):
    for format in ["%Y-%m-%d", "%Y/%m/%d", "%Y.%m.%d", "%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y", "%m/%d/%Y", "%m-%d-%Y",
                   "%m.%d.%Y"]:
        try:
            da = datetime.strptime(date, format).date()
            date_m= datetime.strptime(date, format).month


        except ValueError:
            pass
    for format in ['%Y-%m-%d', '%Y/%m/%d', '%Y.%m.%d', '%d/%m/%Y', '%d-%m-%Y', '%d.%m.%Y', '%m/%d/%Y', '%m-%d-%Y',
                   '%m.%d.%Y']:
        date_str = "2022-08-02"
        try:
            dat = datetime.strptime(date_str, format).date()
        except ValueError:
            pass
    query1= db.query(models.Patient_data.organization,
                     models.Patient_data.ipno,
                     models.Patient_data.isbilldone,
                     models.Patient_data.wardname,
                     models.Patient_data.department,
                     models.Patient_data.adate,
                     models.Patient_data.branch)\
        .where(models.Patient_data.adate==date,
               models.Patient_data.branch==branch,
               models.Patient_data.organization!='Medicover Associate',
               models.Patient_data.organization!='MEDICOVER HOSPITAL',
               models.Patient_data.organization!='MEDICOVER CONSULTANT',
               models.Patient_data.department!='NEPHROLOGY',
               models.Patient_data.isbilldone!='Hold',
               models.Patient_data.isbilldone!='Canceled',
               models.Patient_data.wardname!='DIALYSIS').count()

    query2 = db.query(models.Admission.plan).where(models.Admission.date == date,
                                                   models.Admission.branch == branch).first()
    query3 = db.query(models.Patient_data.organization,
                      models.Patient_data.ipno,
                      models.Patient_data.isbilldone,
                      models.Patient_data.consultant,
                      models.Patient_data.department,
                      models.Patient_data.wardname,
                      models.Patient_data.branch,
                      models.Patient_data.adate) \
        .where(models.Patient_data.adate.between(dat, da),
               models.Patient_data.branch == branch,
               models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
               models.Patient_data.wardname != 'DAY CARE',
               models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
               models.Patient_data.department != 'NEPHROLOGY',
               models.Patient_data.wardname != 'DAY CARE',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.isbilldone != 'Hold').count()

    query = query2.plan
    Ach_p = round((query1 / query) * 100, 2)
    gap = query1 - query

    query4 = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                      models.admission_dummy.status).filter(models.admission_dummy.branch == branch).first()
    clustername = query4[0]
    cname = query4[1]
    status = query4[2]
    return {"admission":query1,"Achieved_p":Ach_p, "gap":gap, "plan":query, "mtd": query3, "clustername":clustername, "cname":cname, "status":status}

@app.post('/Vizag Unit 4')
def Vizag_Unit_4(date:str, branch:str, db:Session=Depends(get_db)):
    for format in ["%Y-%m-%d", "%Y/%m/%d", "%Y.%m.%d", "%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y", "%m/%d/%Y", "%m-%d-%Y",
                   "%m.%d.%Y"]:
        try:
            da = datetime.strptime(date, format).date()
            date_m= datetime.strptime(date, format).month


        except ValueError:
            pass
    for format in ['%Y-%m-%d', '%Y/%m/%d', '%Y.%m.%d', '%d/%m/%Y', '%d-%m-%Y', '%d.%m.%Y', '%m/%d/%Y', '%m-%d-%Y',
                   '%m.%d.%Y']:
        date_str = "2022-08-02"
        try:
            dat = datetime.strptime(date_str, format).date()
        except ValueError:
            pass
    query1= db.query(models.Patient_data.admntype,
                     models.Patient_data.ipno,
                     models.Patient_data.isbilldone,
                     models.Patient_data.branch)\
        .where(models.Patient_data.adate==date,
               models.Patient_data.branch==branch,
               models.Patient_data.isbilldone != 'Hold',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.admntype!='D').count()

    query2 = db.query(models.Admission.plan).where(models.Admission.date == date,
                                                   models.Admission.branch == branch).first()

    query3 = db.query(models.Patient_data.organization,
                      models.Patient_data.ipno,
                      models.Patient_data.isbilldone,
                      models.Patient_data.consultant,
                      models.Patient_data.department,
                      models.Patient_data.wardname,
                      models.Patient_data.branch,
                      models.Patient_data.adate) \
        .where(models.Patient_data.adate.between(dat, da),
               models.Patient_data.branch == branch,

               models.Patient_data.admntype != 'D',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.isbilldone != 'Hold').count()

    query = query2.plan
    Ach_p = round((query1 / query) * 100, 2)
    gap = query1 - query
    query4 = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                      models.admission_dummy.status).filter(models.admission_dummy.branch == branch).first()
    clustername = query4[0]
    cname = query4[1]
    status = query4[2]
    return {"admission":query1,"Achieved_p":Ach_p, "gap":gap, "plan":query, "mtd": query3, 'clustername':clustername, "cname":cname, "status":status}

@app.post('/Sangamner')
def Sangamner(date:str, branch:str, db:Session=Depends(get_db)):
    for format in ["%Y-%m-%d", "%Y/%m/%d", "%Y.%m.%d", "%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y", "%m/%d/%Y", "%m-%d-%Y",
                   "%m.%d.%Y"]:
        try:
            da = datetime.strptime(date, format).date()
            date_m= datetime.strptime(date, format).month


        except ValueError:
            pass
    for format in ['%Y-%m-%d', '%Y/%m/%d', '%Y.%m.%d', '%d/%m/%Y', '%d-%m-%Y', '%d.%m.%Y', '%m/%d/%Y', '%m-%d-%Y',
                   '%m.%d.%Y']:
        date_str = "2022-08-02"
        try:
            dat = datetime.strptime(date_str, format).date()
        except ValueError:
            pass
    query1 = db.query(models.Patient_data.organization,
                      models.Patient_data.ipno,
                      models.Patient_data.isbilldone,
                      models.Patient_data.wardname,
                      models.Patient_data.adate,
                      models.Patient_data.branch) \
        .where(models.Patient_data.adate == date,
               models.Patient_data.branch == branch,
               models.Patient_data.organization != 'Medicover Associate',
               models.Patient_data.organization != 'MEDICOVER HOSPITAL',
               models.Patient_data.organization != 'MEDICOVER CONSULTANT',
               models.Patient_data.isbilldone != 'Hold',
               models.Patient_data.isbilldone != 'Canceled',

               models.Patient_data.wardname != 'DIALYSIS WARD').count()

    query2 = db.query(models.Admission.plan).where(models.Admission.date == date,
                                                   models.Admission.branch == branch).first()
    query3 = db.query(models.Patient_data.organization,
                      models.Patient_data.ipno,
                      models.Patient_data.isbilldone,
                      models.Patient_data.consultant,
                      models.Patient_data.department,
                      models.Patient_data.wardname,
                      models.Patient_data.branch,
                      models.Patient_data.adate) \
        .where(models.Patient_data.adate.between(dat, da),
               models.Patient_data.branch == branch,
               models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
               models.Patient_data.wardname != 'DAY CARE',
               models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
               models.Patient_data.department != 'NEPHROLOGY',
               models.Patient_data.wardname != 'DAY CARE',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.isbilldone != 'Hold').count()
    query = query2.plan
    Ach_p = round((query1 / query) * 100, 2)
    gap = query1 - query

    query4 = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                      models.admission_dummy.status).filter(models.admission_dummy.branch == branch).first()
    clustername = query4[0]
    cname = query4[1]
    status = query4[2]

    return {"admission": query1, "Achieved_p": Ach_p, "gap": gap, "plan": query, "mtd": query3, "clustername":clustername, "cname":cname, "status":status}


@app.post('/Kakinada')
def Kakinada(date:str, branch:str, db:Session=Depends(get_db)):
    for format in ["%Y-%m-%d", "%Y/%m/%d", "%Y.%m.%d", "%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y", "%m/%d/%Y", "%m-%d-%Y",
                   "%m.%d.%Y"]:
        try:
            da = datetime.strptime(date, format).date()
            date_m= datetime.strptime(date, format).month


        except ValueError:
            pass
    for format in ['%Y-%m-%d', '%Y/%m/%d', '%Y.%m.%d', '%d/%m/%Y', '%d-%m-%Y', '%d.%m.%Y', '%m/%d/%Y', '%m-%d-%Y',
                   '%m.%d.%Y']:
        date_str = "2022-08-02"
        try:
            dat = datetime.strptime(date_str, format).date()
        except ValueError:
            pass
    query1= db.query(models.Patient_data.organization,
                     models.Patient_data.ipno,
                     models.Patient_data.isbilldone,
                     models.Patient_data.wardname,
                     models.Patient_data.department,
                     models.Patient_data.adate,
                     models.Patient_data.branch)\
        .where(models.Patient_data.adate==date,
               models.Patient_data.branch==branch,
               models.Patient_data.organization!='Medicover Associate',
               models.Patient_data.organization!='MEDICOVER HOSPITAL',
               models.Patient_data.organization!='MEDICOVER CONSULTANT',
               models.Patient_data.department!='RADIATION ONCOLOGY',
               models.Patient_data.isbilldone != 'Hold',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.wardname!='DIALYSIS').count()

    query2 = db.query(models.Admission.plan).where(models.Admission.date == date,models.Admission.branch == branch).first()

    query3 = db.query(models.Patient_data.organization,
                      models.Patient_data.ipno,
                      models.Patient_data.isbilldone,
                      models.Patient_data.consultant,
                      models.Patient_data.department,
                      models.Patient_data.wardname,
                      models.Patient_data.branch,
                      models.Patient_data.adate) \
        .where(models.Patient_data.adate.between(dat, da),
               models.Patient_data.branch == branch,
               models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
               models.Patient_data.wardname != 'DAY CARE',
               models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
               models.Patient_data.department != 'NEPHROLOGY',
               models.Patient_data.wardname != 'DAY CARE',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.isbilldone != 'Hold').count()
    query= query2.plan
    Ach_p = round((query1 / query) * 100, 2)
    gap = query1 - query

    query4 = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                      models.admission_dummy.status).filter(models.admission_dummy.branch == branch).first()
    clustername = query4[0]
    cname = query4[1]
    status = query4[2]
    return {"admission":query1,"Achieved_p":Ach_p, "gap":gap, "plan":query, "mtd":query3, "clus": clustername, "cname":cname, "status":status}

@app.post('/Mci')
def Mci(date:str, branch:str, db:Session=Depends(get_db)):

    for format in ["%Y-%m-%d", "%Y/%m/%d", "%Y.%m.%d", "%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y", "%m/%d/%Y", "%m-%d-%Y",
                   "%m.%d.%Y"]:
        try:
            da = datetime.strptime(date, format).date()
            date_m= datetime.strptime(date, format).month


        except ValueError:
            pass
    for format in ['%Y-%m-%d', '%Y/%m/%d', '%Y.%m.%d', '%d/%m/%Y', '%d-%m-%Y', '%d.%m.%Y', '%m/%d/%Y', '%m-%d-%Y',
                   '%m.%d.%Y']:
        date_str = "2022-08-01"
        if date>=date_str:
            dat = datetime.strptime(date_str, format).date()
        else:
            return {'error': "invalid date"}

    query1= db.query(models.Patient_data.organization,
                     models.Patient_data.ipno,
                     models.Patient_data.isbilldone,
                     models.Patient_data.department,
                     models.Patient_data.wardname,
                     models.Patient_data.adate,
                     models.Patient_data.branch)\
        .where(models.Patient_data.adate==date,
               models.Patient_data.branch==branch,
               models.Patient_data.organization!='Medicover Associate',
               models.Patient_data.organization!='MEDICOVER HOSPITAL',
               models.Patient_data.organization!='MEDICOVER CONSULTANT',
               models.Patient_data.wardname!='DIALY',
               models.Patient_data.isbilldone != 'Hold',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.department!='RADIATION ONCOLOGY').count()

    query2 = db.query(models.Admission.plan).where(models.Admission.date == date,models.Admission.branch == branch).first()

    query3 = db.query(models.Patient_data.organization,
                      models.Patient_data.ipno,
                      models.Patient_data.isbilldone,
                      models.Patient_data.consultant,
                      models.Patient_data.department,
                      models.Patient_data.wardname,
                      models.Patient_data.branch,
                      models.Patient_data.adate)\
        .where(models.Patient_data.adate.bewteen(dat,da),
               models.Patient_data.branch == branch,
               models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
               models.Patient_data.wardname != 'DAY CARE',
               models.Patient_data.consultant != 'SREEDHAR SHARMA MEDAVARAM',
               models.Patient_data.department != 'NEPHROLOGY',
               models.Patient_data.wardname != 'DAY CARE',
               models.Patient_data.isbilldone != 'Canceled',
               models.Patient_data.isbilldone != 'Hold').count()

    query = query2.plan
    Ach_p = round((query1 / query) * 100, 2)
    gap = query1 - query

    query4 = db.query(models.admission_dummy.clustername, models.admission_dummy.cname,
                      models.admission_dummy.status).filter(models.admission_dummy.branch == branch).first()
    clustername = query4[0]
    cname = query4[1]
    status = query4[2]
    return {"admission":query1,"Achieved_p":Ach_p, "gap":gap, "plan":query, "mtd": query3, "clust":clustername, "cname":cname, "status":status}

@app.post("/all_branch/")
def read_items(date: str, branch: Optional[str]=None):

    results = {"items": kurn({"date":date, "branch":branch})}
    if date:
        results.update({"date": date})
    return results









