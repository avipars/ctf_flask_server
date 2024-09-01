# from werkzeug.utils import secure_filename
import datetime
import json
import logging
import os
import re  # regex
import uuid
from random import gauss, uniform

from flask import (Response, abort, redirect, render_template,
                   render_template_string, request, send_from_directory,
                   session, url_for)
from markupsafe import escape

from ctf import app

YEAR = 2029


LOGINS = {}
with open("logins.json") as f:  # load the logins from the file
    LOGINS = json.load(f)

# allowed files and their mime types
ALLOW_MIME = {
    "pdf": "application/pdf",
    "png": "image/png",
    "ico": "image/x-icon",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "txt": "text/plain",
}

RESOURCE_PATH = os.path.join(
    app.root_path, "resources"
)  # Configure the allowed directory


app.secret_key = "MyUb3rSecr3tS355ionK3y"  # key for sessions
# ensure session cookie is httponly
app.config["SESSION_COOKIE_HTTPONLY"] = True
# ensure session cookie is same site
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["REMEMBER_COOKIE_SECURE"] = True  # ensure remember cookie is secure
app.config["SESSION_COOKIE_SECURE"] = True  # ensure session cookie is secure


@app.route("/favicon.ico", methods=["GET"])
def favicon():
    """
    serve the favicon
    """
    return send_from_directory(
        os.path.join(
            app.root_path,
            "static"),
        "favicon.ico",
        mimetype="image/x-icon")


@app.route("/files/<path:filename>", methods=["GET"])
@app.route("/files", defaults={"filename": ""}, methods=["GET"])
def serve_file(filename):
    """
    in charge of serving files from the /resources directory
    """
    # filename = secure_filename(filename) # sanitize the filename

    if "token" not in session:  # if not logged in
        abort(401)

    path = validate_path(filename)
    if not path or not filename:
        logging.error(f"Invalid or unsafe path: {filename}")
        abort(500)

    if not allowed_type(
            filename,
            ALLOW_MIME):  # Check file extension if needed
        logging.error(f"Invalid file extension: {filename}")
        abort(415)

    return (
        send_from_directory(
            RESOURCE_PATH,
            filename,
            as_attachment=True,
            mimetype=ALLOW_MIME[filename.rsplit(".", 1)[1].lower()],
        ),
        200,
    )


def validate_path(path):
    # print(f"Allowed dir {RESOURCE_PATH} VPath: {path}")
    # ensure path is within the allowed directory
    absolute_path = os.path.join(RESOURCE_PATH, path)
    if not absolute_path.startswith(RESOURCE_PATH):
        return False
    if is_bad(path):  # if null byte (encoded or not), return false
        return False
    # not safe
    if not RESOURCE_PATH == os.path.commonpath((RESOURCE_PATH, absolute_path)):
        return False
    # check if path exists and is a file
    if not os.path.exists(absolute_path) or not os.path.isfile(absolute_path):
        return False
    return absolute_path


def allowed_type(filename, exts=ALLOW_MIME):
    """
    file types that are allowed to be shown to user
    """
    if is_bad(filename):  # if null byte (encoded or not), return false
        return False

    # only care about exts keys not values
    return "." in filename and filename.rsplit(
        ".", 1)[1].lower() in exts.keys()


def is_bad(path):
    # bad stuff to check for, .. for dir trav, %2e%2e for url encoded .., \x00
    # for null byte
    bad_stuff = ("..", "%2e%2e", "\x00", "%00")
    for bad in bad_stuff:
        if bad in path:
            return True
    return False


@app.route("/", methods=["GET"])
@app.route("/index.html", methods=["GET"])
@app.route("/index", methods=["GET"])
@app.route("/home", methods=["GET"])
def index():
    return render_template("home.html", title="Welcome to ColaCo"), 200


@app.route("/logout", methods=["GET"])
@app.route("/logout.html", methods=["GET"])
def logout():
    [session.pop(key, None)
     for key in list(session.keys())]  # clear the session data
    return redirect(url_for("index"), code=302)  # redirect to index


# require user and password via get query parameters
# login.html via POST ONLY, deliver page and when they login with right
# credentials, redirect to admin.html
@app.route("/login", methods=["GET", "POST"])
@app.route("/login.html", methods=["GET", "POST"])
def login():
    # if already logged in, then redirect to admin and pass the username
    if "token" in session and "username" in session:
        user = session["username"]
        return redirect(url_for("admin"), code=302)

    error = None
    msg = request.args.get("msg")
    if msg:
        error = msg

    # if POST, then check if user and password are correct (login sequence)
    if request.method == "POST":
        user = request.form.get("username", None)
        password = request.form.get("password", None)
        if not user or not password:
            logging.error(f"Missing username or password: {user} {password}")
            error = "Missing username or password"

        # Basic input validation (e.g., disallowing certain characters)
        # limit username to alphanumeric and underscore
        basic_val_user = "^[a-zA-Z0-9_]+$"
        # limit password to alphanumeric and some special characters
        basic_val_pass = "^[a-zA-Z0-9_@#\\$%!&*()+-]+$"
        if not re.match(
                basic_val_user,
                user) or not re.match(
                basic_val_pass,
                password):
            logging.error(
                f"Invalid characters in username or password: {user} {password}"
            )
            error = "Invalid characters in username or password"
        else:
            global LOGINS
            if user in LOGINS and LOGINS[user] == password:  # in dict
                session["username"] = user
                session["token"] = str(uuid.uuid4())  # generate a random token
                # redirect to admin route = success
                return redirect(url_for("admin"), code=302)
            else:
                error = "Wrong user or password"
                logging.error(f"{error}: {user} {password}")

    return render_template("login.html", error=error), 200  # render login page


@app.route("/register.html", methods=["GET"])
@app.route("/register", methods=["GET"])
def register():
    # basically say out of service, not implemented
    return (
        render_template(
            "error.html",
            title="Register",
            message="Registration of new accounts is currently not possible.",
        ),
        500,
        # 500, pass the error to be logged by the error handler
    )


@app.route("/admin", methods=["GET"])
@app.route("/admin.html", methods=["GET"])
# ensure the passed in username and password are correct again before
# showing page
def admin():
    if "token" not in session or "username" not in session:
        abort(403)
    else:
        username = session["username"]
        global YEAR  # set year
        current_time = datetime.datetime.now().replace(year=YEAR).strftime("%Y-%m-%d")

        if "sales_data" not in session:  # create sales data once per session
            sales = make_sales_data(year=YEAR)
            session["sales_data"] = sales  # store in session
        else:
            sales = session["sales_data"]  # get from session

        return (
            render_template(
                "dash.html",
                username=username,
                title="User Panel",
                current_time=current_time,
                sales_data=sales,
                notifications=1,  # number of notifications
            ),
            200,
        )


def make_sales_data(year):
    data = []
    today = datetime.datetime.now().replace(year=year)
    for i in range(0, 8):
        date = (today - datetime.timedelta(days=i)).strftime("%m-%d")
        # random sales data
        base_reach = 995

        reach = max(15, int(gauss(base_reach, base_reach * 0.2)))
        sales = max(5, int(reach * uniform(0.05, 0.35)))
        profit = max(0, sales * uniform(0.75, 2.5))

        data.append({"date": date, "sales": sales,
                    "reach": reach, "profit": profit})

    # Calculate the max sales value to normalize the bar heights
    normalized_sales_data = [
        {
            "date": item["date"],
            "sales": item["sales"],
            "reach": item["reach"],
            "profit": round(item["profit"], 2),
        }
        for item in data
    ]

    return normalized_sales_data[::-1]  # old to new


def escape_path_traversal(path):
    while "." in path:
        path = path.replace(".", "")

    path = path.replace("\\", "/")
    return path


# vulnerable route
@app.route("/list_files.html", methods=["GET"])
@app.route("/list_files", methods=["GET"])
def list_files():
    if "token" in session:
        try:
            # The base directory is the '/resources/' directory relative to
            # where run.py is located
            base_dir = RESOURCE_PATH
            # Get the directory to list files from, default to base_dir if not
            # specified
            directory = request.args.get("directory", None)
            if not directory:
                abort(400)
            directory_path = os.path.normpath(
                os.path.join(base_dir, directory)
            )  # Construct the full path
            # we only want directory traversal within the base directory
            # RESOURCE_PATH
            directory = escape_path_traversal(directory)

            # Ensure the directory is within the base directory to avoid
            # outside directory traversal
            if os.path.commonprefix([directory_path, base_dir]) != base_dir:
                abort(403)

            # check if the directory exists and is a directory
            if os.path.exists(directory_path) and os.path.isdir(
                    directory_path):
                # list all files and directories
                items = os.listdir(directory_path)
                for i, item in enumerate(items):
                    item_path = escape(
                        os.path.normpath(
                            os.path.join(
                                directory, item)))
                    # item_path = secure_filename(item_path)

                    logging.info(f"Item path: {item_path}")
                    # linkify the files

                    if os.path.isdir(  # check if it is a directory
                        os.path.join(directory_path, item)
                    ):  # directory
                        items[i] = (
                            f'<a href="/list_files?directory={item_path}">{escape(item)}</a>'
                        )
                    else:  # file
                        items[i] = f'<a href="/files/{item_path}">{escape(item)}</a>'
                return render_template_string("<br>".join(items))
            else:
                abort(404)
        except Exception as e:
            logging.error(f"Error: {e}")
            abort(500)
    else:
        abort(401)  # login required


@app.before_request
def before_request():
    """check user agent and IP"""
    ip = extract_ip()

    user_agent = request.headers.get("User-Agent")
    origin = request.headers.get("Origin")

    print(f"IP: {ip} User-Agent: {user_agent}")
    if origin is not None or request.referrer is not None:
        print(f"Referrer: {request.referrer} Origin: {origin}")

    # always allow things in the static folder, we want favicon, css, robots
    # and sitemap to work
    full_path = os.path.join(app.root_path, "static", request.path.lstrip("/"))
    # check if the file exists
    if os.path.exists(full_path) and os.path.isfile(full_path):
        print(f"Full Path: {full_path}")
        return

    # Initialize or increment the session's failed attempts counter
    if "failed_attempts" not in session:
        session["failed_attempts"] = 0

    # will block functionality in the app if not right
    user_agent = user_agent.strip()
    js_alert = None
    harshness = 15  # number of tries before we dish out more hints
    title = "Invalid User-Agent"
    message = "Please use the latest and most secure corporate browser"
    page = "error.html"
    base_err = render_template(page, title=title, message=message)

    print(f"Failed Attempts: {session['failed_attempts']}")
    if not user_agent.startswith("ColaCoBrowser "):
        logging.warning(f"Invalid UA, no ColaCoBrowser: {user_agent}")
        session["failed_attempts"] += 1

        if session["failed_attempts"] < harshness:
            hint1 = "domo arigato"
            us_err_html = base_err
        else:
            hint1 = "mr roboto.txt"
            js_alert = "hint in HTTP Headers"
            us_err_html = render_template(
                page,
                title=title,
                message=message,
                jsinfo=hint1,
                jsalert=js_alert)
            session["failed_attempts"] = 0

        return Response(
            us_err_html,
            headers={"X-Wrong-Browser": "true", "X-Hint": hint1},
            status=400,
        )

    elif "M9 Ultra" not in user_agent:
        logging.warning(f"Invalid UA, no M9 Ultra: {user_agent}")
        session["failed_attempts"] += 1

        if session["failed_attempts"] < harshness:
            hint1 = "sugar rush"
            hint2 = "prior stage"
            us_err_html = base_err
        else:
            hint1 = "all dns"
            hint2 = "sugar rush cloud ns"
            js_alert = "check the console too"
            us_err_html = render_template(
                page,
                title=title,
                message=message,
                jsinfo=hint2,
                jsalert=js_alert)
            session["failed_attempts"] = 0
        return Response(
            us_err_html,
            headers={
                "X-Wrong-CPU": "true",
                "X-Hint": hint1},
            status=401)
    elif "MacOS XIX" not in user_agent:
        logging.warning(f"Invalid UA, no MacOS XIX: {user_agent}")
        session["failed_attempts"] += 1

        if session["failed_attempts"] < harshness:
            hint1 = "One last thing"
            us_err_html = base_err
        else:
            hint1 = "can't forget the OS"
            js_alert = "If I only had a brain"

            us_err_html = render_template(
                page,
                title=title,
                message=message,
                jsinfo=hint2,
                jsalert=js_alert)
            session["failed_attempts"] = 0

        return Response(
            us_err_html,
            headers={
                "X-Wrong-OS": "true",
                "X-Hint": hint1},
            status=403)
    else:
        session["failed_attempts"] = 0
        logging.info(f"Valid UA: {user_agent}")


def extract_ip():  # get the ip of the user (and store it in a global variable)
    """get the IP of the user"""
    try:
        # avoid's pythonanywhere load balancer IP
        ip = request.headers["X-Real-IP"]  # get the real IP
    except KeyError:  # if no X-Real-IP header, mainly for local-tests
        # get port too
        if request.environ.get("HTTP_X_FORWARDED_FOR") is None:
            ip = request.environ["REMOTE_ADDR"]
        else:
            ip = request.environ["HTTP_X_FORWARDED_FOR"]
        port = request.environ.get("REMOTE_PORT")
        # log this error
        logging.warning(
            f"Error: No X-Real-IP header, using remote_addr {ip} {port}")
    return ip

@app.context_processor
def inject_stuff():
    """
    used for the footer to display the YEAR, version
    """
    return {"year": YEAR, "version": "1.0.0"}

if __name__ == "__main__":
    print("Running Flask Server from routes.py")
    app.run(debug=False)
