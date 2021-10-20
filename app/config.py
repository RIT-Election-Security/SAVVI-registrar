from os import environ

BALLOT_BOX_URL = environ.get("BALLOT_BOX_URL", "http://localhost:5001")
DATABASE_URL = environ.get("DATABASE_URL", "sqlite:///data/sqlite.db")
RESULTSERVER_URL = environ.get("RESULTSERVER_URL", "http://localhost:5002")
ALLOW_ORIGIN = environ.get("ALLOW_ORIGIN")
