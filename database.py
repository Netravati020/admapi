
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import pymysql
from sqlalchemy.ext.declarative import declarative_base

sql_database_url= "mysql+pymysql://root@localhost:3306/admission"
engine= create_engine(sql_database_url)
SessionLocal= sessionmaker(autocommit=False,autoflush=False, bind=engine)
conn=engine.connect()


Base= declarative_base()
print("connected")
