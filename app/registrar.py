from quart import Quart, abort, flash, render_template, redirect, url_for, request
from quart_auth import AuthManager, AuthUser, Unauthorized, current_user, login_user, logout_user, login_required
from secrets import token_urlsafe

from .ballotbox_utils import decode_decrypt_load_dict, generate_ballot_details_token
from .database import add_token_id, add_user, check_token_is_valid, get_user_voted_status, create_session, get_user_ballot_details, set_user_voted_status_true, verify_user_password


app = Quart(__name__)
AuthManager(app)
app.config["QUART_AUTH_COOKIE_NAME"] = "quart_auth_registrar"
app.secret_key = token_urlsafe(16)

try:
    app.config.from_pyfile("config.py")
except FileNotFoundError:
    print("Config file not found")

try:
    app.config.from_pyfile("secret_config.py")
except FileNotFoundError:
    print("Secrets config file not found")

app.db_session = create_session(app.config.get("DATABASE_URL"))


@app.errorhandler(Unauthorized)
async def redirect_to_login(*_: Exception):
    """
    If unauthorized, send use to login page

    Args:
        Error(s)
    Returns:
        Redirect to login page
    """
    return redirect(url_for("login"))


@app.route("/")
async def home():
    """
    Render the homepage, some alterations if user authenticated and/or has voted.

    Returns:
        Rendered homepage
    """
    resultserver_url = app.config.get("RESULTSERVER_URL")
    user_has_voted = None
    if await current_user.is_authenticated:
        user_has_voted = get_user_voted_status(app.db_session, current_user.auth_id)
    return await render_template("home.html", user_has_voted=user_has_voted, resultserver_url=resultserver_url)


@app.route("/login", methods=["GET", "POST"])
async def login():
    """
    GET: Render the login page.
    POST: Verify login credentials and proceed accordingly.

    Returns:
        Rendered login template if method is GET
        Rendered login template with error message if credentials are invalid
        Redirect to homepage if credentials are valid

    # TODO multi-factor authentication
    """
    if request.method == "GET":
        return await render_template("login.html")
    elif request.method == "POST":
        form = await request.form
        email = form.get("email")
        submitted_passwd = form.get("password")
        if verify_user_password(app.db_session, email, submitted_passwd):
            login_user(AuthUser(email))
            return redirect(url_for("home"))
        else:
            await flash("Invalid credentials, login failed")
            return await render_template("login.html")


@app.route("/logout")
async def logout():
    """
    Log a user out.

    Return:
        Redirect to the homepage
    """
    logout_user()
    return redirect(url_for("home"))


@app.route("/register", methods=["GET", "POST"])
async def register():
    """
    Register a user's account

    GET: Render the registration template
    POST: Ensure all form components are present, attempt to create user, login new user
        If adding user fails, send error message.

    Returns:
        If method is get returns registration template
        If method is post and information is valid, returns logged in user to homepage
        If method is post and informatoin is invalid returns error message to with registration template
    
    # TODO Submit real proof of ID
    # TODO Setup Multifactor
    """
    if request.method == "GET":
        return await render_template("register.html")
    elif request.method == "POST":
        form = await request.form
        try:
            assert form.get("firstname"), "first name is required"
            assert form.get("lastname"), "last name is required"
            assert form.get("address"), "address is required"
            assert form.get("email"), "email is required"
            assert form.get("password"), "password is required"
            add_user(
                app.db_session,
                form["firstname"],
                form["lastname"],
                form["address"],
                form["email"],
                form["password"]
            )
            login_user(AuthUser(form["email"]))
            return redirect(url_for('home'))
        except AssertionError as e:
            await flash(e)
            return await render_template("register.html")


@app.route("/checkin", methods=["GET"])
@login_required
async def checkin():
    """
    Present a logged in user with a ballotbox token.
    If user has already voted, present them with a message to view results at the results server.

    Returns:
        Rendered template of checkin page
    
    # TODO Require within polling hours
    """
    user_has_voted = get_user_voted_status(app.db_session, current_user.auth_id)
    ballot_box_url = app.config.get("BALLOT_BOX_URL")
    if user_has_voted:
        token = None    
    else:
        ballot_details = get_user_ballot_details(app.db_session, current_user.auth_id)
        token_id = add_token_id(app.db_session, current_user.auth_id)
        token = generate_ballot_details_token(ballot_details, token_id, app.config.get("SHARED_KEY"))
    return await render_template("checkin.html", token=token, ballot_box_url=ballot_box_url, user_has_voted=user_has_voted)


@app.route("/voter/<endpoint>", methods=["POST"])
async def user_voted(endpoint: str):
    """
    Doesn't require authentication, but parameter values are encrypted with secret key

    If endpoint is token, check if token is valid (consumes the token)
    If endpoint is voted, record that a user has voted

    Args:
        endpoint: should be either 'token' or 'valid'
    Returns:
        token: Valid if token is valid, invalid if not
        voted: Okay after user voted status set to true
    """
    try:
        data = await request.data
        form = decode_decrypt_load_dict(data, app.config.get("SHARED_KEY"))
        assert form.get("voter_number"), "voter_number is required"
        voter_number = form["voter_number"]
        if endpoint == "token":
            assert form.get("token_id"), "token_id is required"
            token_id = form["token_id"]
            if check_token_is_valid(app.db_session, voter_number, token_id):
                return "valid", 200
            else:
                return "invalid", 200
        elif endpoint == "voted":
            set_user_voted_status_true(app.db_session, voter_number)
            return "okay", 200
        else:
            abort(404)
    except AssertionError as e:
        abort(400, e)


if __name__ == "__main__":
    from . import app
    app.run(debug=True)
