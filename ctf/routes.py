import logging
import os
import re  # regex
import uuid
from ctf import app
from flask import request ,session
from flask import redirect, render_template, send_from_directory, abort, url_for, render_template_string
from markupsafe import escape
from werkzeug.utils import secure_filename

 
ALLOW_LIST = {'pdf', 'png', 'jpg', 'jpeg', 'gif','txt'}
# from user_agents import parse
# from werkzeug.useragents import UserAgent

# Hardcoded logins
LOGINS = {"eileen": "FamousZebraFumbles75",
          "scotty": "you will never#@@guess this password"}

app.secret_key = "MyUb3rSecr3tS355ionK3y" # key for sessions

RESOURCE_PATH = os.path.join(app.root_path, 'resources') # Configure the allowed directory


@app.route('/files/<path:filename>')
@app.route('/files', defaults={'filename': ''})
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

    if not allowed_type(filename, ALLOW_LIST):   # Check file extension if needed
        logging.error(f"Invalid file extension: {filename}")
        abort(415)

    return send_from_directory(RESOURCE_PATH, filename)

def validate_path(path):
    print(f"Allowed dir {RESOURCE_PATH} VPath: {path}")
    # ensure path is within the allowed directory
    absolute_path = os.path.join(RESOURCE_PATH, path)
    if not absolute_path.startswith(RESOURCE_PATH):
        return False
    if is_bad(path):  # if null byte (encoded or not), return false
        return False
    if not RESOURCE_PATH == os.path.commonpath((RESOURCE_PATH, absolute_path)): # not safe
        return False
    if not os.path.exists(absolute_path) or not os.path.isfile(absolute_path):     # check if path exists and is a file
        return False
    return absolute_path

def allowed_type(filename, exts=ALLOW_LIST):
    """
    file types that are allowed to be shown to user 
    """
    if is_bad(filename):  # if null byte (encoded or not), return false
        return False
    
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in exts

def is_bad(path):
    bad_stuff = ('..', '%2e%2e', '\x00','%00') # bad stuff to check for, .. for dir trav, %2e%2e for url encoded .., \x00 for null byte
    for bad in bad_stuff:
        if bad in path:
            return True
    return False
     
@app.route("/")
@app.route("/index.html")
@app.route("/index")
@app.route("/home")
def index():
    return render_template("home.html", title="Welcome to ColaCo's Website"), 200

@app.route("/logout")
@app.route("/logout.html")
def logout():
    session.pop("token", None)   # remove the token from the session
    return redirect(url_for("index"), code=302)

# require user and password via get query parameters
# login.html via POST ONLY, deliver page and when they login with right credentials, redirect to admin.html
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

    if request.method == "POST":
        user = request.form.get("username")
        password = request.form.get("password")
        # Basic input validation (e.g., disallowing certain characters)
        basic_val = "^[a-zA-Z0-9_]+$" 
        if not re.match(basic_val, user) or not re.match(basic_val, password):
            logging.error(f"Invalid characters in username or password: {user} {password}")
            error = "Invalid characters in username or password"
        else:
            if user in LOGINS and LOGINS[user] == password:  # in dict
                session["username"] = user
                session["token"] = str(uuid.uuid4())  # generate a random token
                return redirect(url_for("admin", username=user), code=302)      # redirect to admin.html
            else:
                logging.error(f"Wrong user or password: {user} {password}")
                error = "Wrong user or password"
    return render_template("login.html", error=error), 200


@app.route("/register.html")
@app.route("/register")
def register():
    # basically say out of service, not implemented
    return render_template("message.html", title="Register", message="Registering is not implemented"), 500

@app.route("/admin", methods=['GET'])
@app.route("/admin.html", methods=['GET'])
# ensure the passed in username and password are correct again before showing page
def admin():
    if "token" not in session:
        abort(403)
    else:
        user = request.args.get("username")
        return render_template("dash.html", username=user, title="User Panel"), 200


def escape_path_traversal(path):
    while '.' in path:
        path = path.replace('.', '')
        
    path = path.replace("\\","/")
    return path


# vulnerable route
@app.route('/list_files.html', methods=['GET'])
@app.route('/list_files', methods=['GET'])
def list_files():
    if "token" in session:
        try:
            base_dir = RESOURCE_PATH      # The base directory is the '/resources/' directory relative to where run.py is located
            directory = request.args.get('directory', '')             # Get the directory to list files from, default to base_dir if not specified
            directory_path = os.path.normpath(os.path.join(base_dir, directory))             # Construct the full path
            # we only want directory traversal within the base directory RESOURCE_PATH
            directory = escape_path_traversal(directory)
            
            # Ensure the directory is within the base directory to avoid outside directory traversal
            if os.path.commonprefix([directory_path, base_dir]) != base_dir:
                abort(403)

            # check if the directory exists and is a directory
            if os.path.exists(directory_path) and os.path.isdir(directory_path):
                items = os.listdir(directory_path)                 # list all files and directories
                for i, item in enumerate(items):
                    item_path = escape(os.path.normpath(os.path.join(directory, item)))
                    # item_path = secure_filename(item_path)

                    logging.info(f"Item path: {item_path}")
                    # linkify the files

                    if os.path.isdir(os.path.join(directory_path, item)):    # directory
                        items[i] = f'<a href="/list_files?directory={item_path}">{escape(item)}</a>'
                    else:
                        items[i] = f'<a href="/files/{item_path}">{escape(item)}</a>'
                return render_template_string('<br>'.join(items) )
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


def extract_ip():  # get the ip of the user (and store it in a global variable)
    """get the IP of the user"""
    try:
        # avoid's pythonanywhere load balancer IP
        ip = request.headers["X-Real-IP"]
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
    return render_template("message.html", title="415 Unsupported Media Type", message="Sorry, the server cannot process the media type"), 415

@app.errorhandler(400)
def bad_request(e):
    # note that we set the 400 status explicitly
    logging.error(f"400: {request.url}")
    return render_template("message.html", title="400 Bad Request", message="Sorry, your request could not be processed"), 400

@app.errorhandler(401)
def unauthorized(e):
    # note that we set the 401 status explicitly
    logging.error(f"401: {request.url}")
    return render_template("message.html", title="401 Unauthorized", message="Sorry, your request could not be processed"), 401

@app.errorhandler(403)
def forbidden(e):
    # note that we set the 403 status explicitly
    logging.error(f"403: {request.url}")
    return render_template("message.html", title="403 Forbidden", message="Access to this resource on this server is forbidden"), 403

@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    logging.error(f"404: {request.url}")
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_server_error(e):
    # note that we set the 500 status explicitly
    logging.error(f"500: {request.url}")
    return render_template("message.html", title="500 Internal Server Error", message="Try again later"), 500


if __name__ == "__main__":
    print("Running Flask Server from routes.py")
    app.run(debug=False)
