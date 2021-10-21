from app import app
from app.database import add_eligible_voters


def runserver(host_address: str="0.0.0.0", port: int=5000, debug: bool=False, key: str=None, cert: str=None):
    """
    Run the registrar application server.

    Args:
        host_address: address to bind to
        port: port number to bind to
        debug: toggle debug mode
    """
    if (key or cert) and not key or not cert:
        print("Both cert and key required if one presented")
        exit(1)

    app.run(debug=debug, host=host_address, port=port, keyfile=key, certfile=cert)


def addvoters(sqlfile: str=None, jsonfile: str=None, strict: bool=False):
    """
    Add eligible voters to the app's databse

    Args:
        sqlfile: SQLite script to add voter data (not yet supported)
        jsonfile: jsonfile
        strict: Cancel adding all users if one fails
    """
    from json import load
    if sqlfile:
        # TODO: this but maybe not
        print("Operation not yet supported")
    elif jsonfile:
        with open(jsonfile) as f:
            voters = load(f)
        try:
            add_eligible_voters(app.db_session, voters, strict=strict)
        except ValueError as e:
            print(e)
    else:
        print("Missing -jsonfile or -slqfile")


if __name__ == "__main__":
    from argparse import ArgumentParser

    parser = ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", help="Available actions")

    runserver_parser = subparsers.add_parser("runserver", help="Run the application")
    runserver_parser.add_argument("-debug", action="store_true", help="Run app in debug mode")
    runserver_parser.add_argument("-a", "--addr", type=str, default="0.0.0.0", help="Host to bind app to")
    runserver_parser.add_argument("-p", "--port", type=int, default=5000, help="Port to bind app to")
    runserver_parser.add_argument("-key", type=str, help="Path to TLS key file")
    runserver_parser.add_argument("-cert", type=str, help="Path to TLS certificate file")
    
    addusers_parser = subparsers.add_parser("addvoters", help="Add eligible voters to the database")
    addusers_parser.add_argument("-sqlfile", help="SQLite file with voter data")
    addusers_parser.add_argument("-jsonfile", help="JSON file with voter data")
    addusers_parser.add_argument("-strict", action="store_true", help="Cancel operation if any records fail")

    args = parser.parse_args()

    if args.action == "runserver":
        runserver(args.addr, args.port, debug=args.debug, key=args.key, cert=args.cert)
    elif args.action == "addvoters":
        addvoters(sqlfile=args.sqlfile, jsonfile=args.jsonfile)
