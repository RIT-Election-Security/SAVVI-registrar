from sqlalchemy import create_engine, and_
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import NoResultFound
from os import urandom
from uuid import uuid4
import scrypt

from .models import Base, EligibleVoter, Token, User
from .ballotbox_utils import BallotDetails


def create_session(url: str) -> Session:
    """
    Create a database session

    Args:
        url: url to the database
    Returns:
        A database session object
    """
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    return Session(engine)


def hash_password(password: str, maxtime: int=1, length: int=64) -> bytes:
    """
    Hash a password string using scrypt

    Args:
        password: password string
        maxtime: maximum timed decryption should take
        length: length of key to generate
    Returns:
        Hashed password
    """
    return scrypt.encrypt(urandom(length).hex(), password, maxtime=maxtime)


def verify_password(candidate: str, hash: bytes, maxtime: int=5) -> bool:
    """
    Verify candidate password matches hash

    Args:
        candidate: password to check against hash
        hash: hash to check password against
        maxtime: maximum time allowed to check hash
    Returns:
        True if password successfully matches hash (decrypts scrypt encrypted value)
        False if passworrd fails to match hash (decrypt scrypt encrypted value)
    """
    try:
        scrypt.decrypt(hash, candidate, maxtime)
        return True
    except scrypt.error:
        return False


def verify_user_password(session: Session, email: str, candidate_password: str) -> bool:
    """
    Verify a users password is correct.

    Args:
        session: database session
        email: user email address
        candidate_password: password to check against hashed password
    Returns:
        True if user exists and password is correct
        False if user does not exist or password is incorrect
    """
    user = session.query(User).filter(User.email == email).one_or_none()
    try:
        assert user
        return verify_password(candidate_password, user.password)
    except AssertionError:
        return False


def add_eligible_voters(session: Session, voters: list, strict: bool=True):
    """
    Add a list of eligible voter data to the database.
    Voter data must follow this pattern:

        {
            "first": "Jim",
            "last": "Smith",
            "address": "12 Three Street",
            "ballot_style": "ballot-style-01"
        }
    
    ballot_styles should correspond to a ballot_style in the election manifest.

    Args:
        session: database session
        voters: list of dicts of voter data
        strict: if True, abort and rollback all entries if one entry fails to add
    Raises:
        ValueError if entry is missing a required field
    """
    for voter in voters:
        try:
            assert voter.get("first"), "first"
            assert voter.get("last"), "last"
            assert voter.get("address"), "address"
            assert voter.get("ballot_style"), "ballot_style"
            eligible_voter = EligibleVoter(
                voter_number=f"voter-{uuid4()}",
                first=voter["first"],
                last=voter["last"],
                address=voter["address"],
                ballot_style=voter["ballot_style"]
            )
            session.add(eligible_voter)
        except AssertionError as e:
            if strict:
                session.rollback()
                raise ValueError(f"Voter {voter} missing required field: {e}")
    session.commit()


def add_user(session: Session, firstname: str, lastname: str, address: str, email: str, password: str):
    """
    Add a user to the application database.
    Confirms information matches with eligible voter database.
    Confirms makes sure email is not already in use.
    Creates new user once above validated.

    Args:
        session: database session
        firstname: user first name (should be in eligible_voters)
        lastname: user last name (should be in eligible_voters)
        address: user address (should be in eligible_voters)
        email: user email address
        password: user password
    Raises:
        AssertionError: if voter is not found
                        if voter already has an account registered
                        if email is already in use
    """
    # Check if user in eligible voters database
    try:
        voter = (session.query(EligibleVoter).filter(
                and_(EligibleVoter.first == firstname,
                     EligibleVoter.last == lastname,
                     EligibleVoter.address == address)).one())
    except NoResultFound as e:
        raise AssertionError("Voter not found")
    # If voter query doesn't return unique ID, fail
    # TODO THIS IS NOT A REALISTIC CHECK FOR ACCOUNT ELIGIBILITY!
    # FOR PoC PURPOSES ONLY
    # Make sure account is unique
    assert not voter.has_account, "Voter already registered"

    # Make sure email is unique
    assert not session.query(User).filter(User.email == email).one_or_none(), "Email already in use"

    # Create and add new user
    user = User(
        email=email,
        password=hash_password(password),
        name=f"{firstname} {lastname}",
        has_voted=False,
        voter_number=voter.voter_number,
    )
    session.add(user)
    # Make sure voter cannot have another account made for them
    voter.has_account = True
    session.commit()


def add_token_id(session: Session, email: str) -> str:
    """
    Generate a token ID and add it to the database.
    All previous tokens issued to the user are marked as used.

    Args:
        session: database session
    Returns:
        Generated token ID
    """
    # Get user object
    user = session.query(User).filter(User.email == email).one()
    # Get all tokens previously issued to the user and invalidate them
    previous_tokens = session.query(Token).filter(Token.voter_number == user.voter_number)
    for token in previous_tokens:
        token.used = True
    # Create token ID
    token_id = f"token-{uuid4()}"
    # Create and add new token
    token = Token(token_id=token_id, voter_number = user.voter_number)
    session.add(token)
    session.commit()
    return token_id


def get_user_ballot_details(session: Session, email: str) -> BallotDetails:
    """
    Get ballot details for a user by ID.

    Args:
        session: database session
        email: user email
    Returns:
        Ballotdetails object with ballot_style and voter_number
    
    # TODO Two queries is probably slow
    """
    user = session.query(User).filter(User.email == email).one()
    voter_data = session.query(EligibleVoter).filter(EligibleVoter.voter_number == user.voter_number).one()
    details = BallotDetails(voter_data.ballot_style, voter_data.voter_number)
    return details


def get_user_voted_status(session: Session, email: str) -> bool:
    """
    Check if a user has voted.

    Args:
        session: database session
        email: user email
    Returns:
        True if the user has voted and false if not
    """
    user = session.query(User).filter(User.email == email).one()
    return user.has_voted


def set_user_voted_status_true(session: Session, voter_number: str):
    """
    Record that a user has voted.

    Args:
        session: database session
        voter_number: user voter number
    """
    user = session.query(User).filter(User.voter_number == voter_number).one()
    user.has_voted = True
    session.commit()


def check_token_is_valid(session: Session, voter_number: str, token_id: str) -> bool:
    """
    Check if a token is valid (voter_number and token_id).
    Consumes the token and marks as used.

    Args:
        session: database session
        voter_number: user voter number
        token_id: token string
    Returns:
        Returns True if user has not voted and token has not been used yet
    """
    user = session.query(User).filter(User.voter_number == voter_number).one()
    token = session.query(Token).filter(Token.token_id == token_id).one()
    valid = not user.has_voted and not token.used
    token.used = True
    session.commit()
    return valid
