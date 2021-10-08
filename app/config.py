from os import environ

BALLOT_BOX_ENDIANNESS = environ.get("BALLOTBOX_ENDIANNESS", "big")
BALLOT_BOX_URL = environ.get("BALLOT_BOX_URL", "http://localhost:5001")
DATABASE_URL = environ.get("DATABASE_URL", "sqlite:///.sqlite.db")
RESULTSERVER_URL = environ.get("RESULTSERVER_URL", "http://localhost:5002")
