import datetime
import logging
import os
import random
import re  # regex
import uuid

from flask import (abort, redirect, render_template, render_template_string,
                   request, send_from_directory, session, url_for, jsonify, Response, abort)
from markupsafe import escape
from werkzeug.utils import secure_filename
import base64
import random

from ctf import app

right_values=False 
# allowed files and their mime types
ALLOW_MIME = {
    "pdf": "application/pdf",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "txt": "text/plain",
}
# from user_agents import parse
# from werkzeug.useragents import UserAgent

# Hardcoded logins
LOGINS = {
    "eileen": "FamousZebraFumbles75",
    "scotty": "youwillnever#@@guessthispassword",
}

app.secret_key = "MyUb3rSecr3tS355ionK3y"  # key for sessions
# ensure session cookie is httponly
app.config["SESSION_COOKIE_HTTPONLY"] = True
# ensure session cookie is same site
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["REMEMBER_COOKIE_SECURE"] = True  # ensure remember cookie is secure
app.config["SESSION_COOKIE_SECURE"] = True  # ensure session cookie is secure

RESOURCE_PATH = os.path.join(
    app.root_path, "resources"
)  # Configure the allowed directory

# Define the virtual file system
virtual_file_system = {
    "root": {
        "folder1": {
            "file1.txt": "This is the content of file1.txt",
            "subfolder1": {
                "file2.txt": "This is the content of file2.txt"
            }
        },
        "folder2": {
            "file3.txt": "This is the content of file3.txt",
            "subfolder2": {
                "file4.txt": "This is the content of file4.txt",
                "subsubfolder1": {
                    "file5.txt": "This is the content of file5.txt"
                }
            }
        }
    }
}


# Helper function to traverse the virtual file system
def traverse_virtual_fs(path_parts, current_dir):
    global right_values
    if not right_values:
        abort(403)
        
    if not path_parts:
        return current_dir  # Return the current directory or file content
    part = path_parts.pop(0)
    if part in current_dir:
        return traverse_virtual_fs(path_parts, current_dir[part])
    else:
        # print the root directory
        return virtual_file_system['root']
        abort(404)  # If the path part doesn't exist, return 404

@app.route('/files2/<path:file_path>', methods=['GET'])
def get_file(file_path):
    
    ua = request.headers.get('User-Agent','')
    ref = request.headers.get('Referer','')
    if 'colaco' not in ua.lower():
        return 'Only ColaCo employees are allowed to access this resource', 403
    print(f"User-Agent: {ua} Referer: {ref}")
    path_parts = file_path.split('/')
    content = traverse_virtual_fs(path_parts, virtual_file_system['root'])

    
    if isinstance(content, dict):
        # It's a directory, return its contents as JSON
        return jsonify({"contents": list(content.keys())})
    else:
        # It's a file, return its content
        return Response(content, mimetype="text/plain")

def obfuscate(content):
    return base64.b64encode(content.encode()).decode()

def deobfuscate(content):
    return base64.b64decode(content.encode()).decode()

# favicon


@app.route("/favicon.ico", methods=["GET"])
def favicon():
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
    if "token" not in session:
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
    return render_template(
        "home.html", title="Welcome to ColaCo's Website"), 200


@app.route("/logout", methods=["GET"])
@app.route("/logout.html", methods=["GET"])
def logout():
    session.pop("username", None)  # remove the username from the session
    session.pop("token", None)  # remove the token from the session
    session.pop("sales_data", None)  # remove the sales data from the session
    return redirect(url_for("index"), code=302)


# require user and password via get query parameters
# login.html via POST ONLY, deliver page and when they login with right
# credentials, redirect to admin.html
@app.route("/login", methods=["GET", "POST"])
@app.route("/login.html", methods=["GET", "POST"])
def login():
    # if already logged in, then redirect to admin and pass the username
    if "token" in session and "username" in session:
        user = session["username"]
        return redirect(url_for("admin", username=user), code=302)

    error = None
    msg = request.args.get("msg")
    if msg:
        error = msg

    # if POST, then check if user and password are correct (login sequence)
    if request.method == "POST":
        user = request.form.get("username", "")
        password = request.form.get("password", "")
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
            if user in LOGINS and LOGINS[user] == password:  # in dict
                session["username"] = user
                session["token"] = str(uuid.uuid4())  # generate a random token
                return redirect(
                    url_for("admin", username=user), code=302
                )  # redirect to admin.html
            else:
                error = "Wrong user or password"
                logging.error(f"{error}: {user} {password}")

    return render_template("login.html", error=error), 200


@app.route("/register.html", methods=["GET"])
@app.route("/register", methods=["GET"])
def register():
    # basically say out of service, not implemented
    return (
        render_template(
            "message.html",
            title="Register",
            message="Registering is not possible at the moment",
        ),
        500,
    )


@app.route("/admin", methods=["GET"])
@app.route("/admin.html", methods=["GET"])
# ensure the passed in username and password are correct again before
# showing page
def admin():
    if "token" not in session:
        abort(403)
    else:
        user = request.args.get("username", None)
        # set year to 2029
        current_time = (
            datetime.datetime.now().replace(
                year=2029).strftime("%Y-%m-%d %H:%M:%S"))

        notifications = 1  # number of notifications
        if "sales_data" not in session:
            sales = make_sales_data()
            session["sales_data"] = sales  # store in session
        else:
            sales = session["sales_data"]  # get from session
        return (
            render_template(
                "dash.html",
                username=user,
                title="User Panel",
                current_time=current_time,
                sales_data=sales,
                notifications=notifications,
            ),
            200,
        )


def make_sales_data():
    data = []
    today = datetime.datetime.now().replace(year=2029)
    for i in range(0, 8):
        date = (today - datetime.timedelta(days=i)).strftime("%m-%d")

        sales = random.randint(15, 573)
        reach = random.randint(25, 1000)
        # Profit is a random percentage of sales, but higher sales mean a
        # higher chance of a better profit margin
        profit_margin = random.uniform(
            0.3, 0.6) + (sales - 200) / 500 * random.uniform(0.1, 0.2)
        profit = int(sales * profit_margin)
        data.append({"date": date, "sales": sales,
                    "reach": reach, "profit": profit})

    # Calculate the max sales value to normalize the bar heights
    max_sales = max(item["sales"] for item in data)
    normalized_sales_data = [
        {
            "date": item["date"],
            "sales": int((item["sales"] / max_sales) * 5),
            "reach": item["reach"],
            "profit": item["profit"],
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

                    if os.path.isdir(
                        os.path.join(
                            directory_path,
                            item)):  # directory
                        items[i] = (
                            f'<a href="/list_files?directory={item_path}">{escape(item)}</a>'
                        )
                    else:
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
    # user_agent = UserAgent(request.headers.get("User-Agent"))
    print(f"IP: {ip} User-Agent: {user_agent}")
    # get the referrer
    referer = request.referrer
    print(f"Referer: {referer}")
    # origin
    origin = request.headers.get("Origin")
    print(f"Origin: {origin}")
    if referer != "https://www.colaco.website" and origin != "https://www.colaco.website" and user_agent != "ColaCoBot":
        logging.warning(f"Invalid referer or origin: {referer} {origin} {user_agent}")
        
    else:
        right_values=True
        logging.info(f"Valid referer and origin: {referer} {origin} {user_agent}")
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


@app.errorhandler(415)
def unsupported_media_type(e):
    # note that we set the 415 status explicitly
    logging.error(f"415: {request.url}")
    return (
        render_template(
            "message.html",
            title="415 Unsupported Media Type",
            message="Sorry, the server cannot process the media type",
        ),
        415,
    )


@app.errorhandler(400)
def bad_request(e):
    # note that we set the 400 status explicitly
    logging.error(f"400: {request.url}")
    return (
        render_template(
            "message.html",
            title="400 Bad Request",
            message="Sorry, your request could not be processed",
        ),
        400,
    )


@app.errorhandler(401)
def unauthorized(e):
    # note that we set the 401 status explicitly
    logging.error(f"401: {request.url}")
    return (
        render_template(
            "message.html",
            title="401 Unauthorized",
            message="Sorry, your request could not be processed",
        ),
        401,
    )


@app.errorhandler(403)
def forbidden(e):
    # note that we set the 403 status explicitly
    logging.error(f"403: {request.url}")
    return (
        render_template(
            "message.html",
            title="403 Forbidden",
            message="Access to this resource on this server is forbidden",
        ),
        403,
    )


@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    logging.error(f"404: {request.url}")
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_server_error(e):
    # note that we set the 500 status explicitly
    logging.error(f"500: {request.url}")
    return (
        render_template(
            "message.html",
            title="500 Internal Server Error",
            message="Try again later"),
        500,
    )


if __name__ == "__main__":
    print("Running Flask Server from routes.py")
    app.run(debug=False)
