from sqlalchemy import LargeBinary, Boolean, Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class EligibleVoter(Base):
    __tablename__ = "eligible_voters"
    voter_number = Column(String, primary_key=True)
    first = Column(String)
    last = Column(String)
    address = Column(String)
    ballot_style = Column(String)
    has_account = Column(Boolean, default=False)


class User(Base):
    __tablename__ = "users"
    email = Column(String, primary_key=True)
    password = Column(LargeBinary)
    name = Column(String)
    has_voted = Column(Boolean, default=False)
    voter_number = Column(String, ForeignKey("eligible_voters.voter_number"), unique=True)


class Token(Base):
    __tablename__ = "tokens"
    token_id = Column(String, primary_key=True)
    used = Column(Boolean, default=False)
    voter_number = Column(String, ForeignKey("users.voter_number"))
