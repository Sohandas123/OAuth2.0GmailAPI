from sqlalchemy import create_engine, Column, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class Recipient(Base):
    __tablename__ = 'recipients'
    email = Column(String, primary_key=True)
    public_key = Column(String)  # PEM-formatted RSA public key

engine = create_engine('sqlite:///recipients.db')
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)