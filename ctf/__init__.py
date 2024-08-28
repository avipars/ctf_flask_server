from flask import Flask

from ctf import errors, routes

# from ctf.error_handlers import register_error_handlers  # Adjust the
# import based on your project structure

app = Flask(
    __name__,
    static_folder="static",
    static_url_path="/",
    template_folder="templates",
)

# register_error_handlers(app)
# app.config['referrer_policy'] = 'strict-origin-when-cross-origin'
