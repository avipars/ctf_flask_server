import logging

from flask import render_template, request

from ctf import app


@app.errorhandler(415)
def unsupported_media_type(e):
    # note that we set the 415 status explicitly
    logging.error(f"415: {request.url} {e}")

    return (
        render_template(
            "error.html",
            title="415 Unsupported Media Type",
            message="Sorry, the server cannot process the media type",
        ),
        415,
    )


@app.errorhandler(400)
def bad_request(e):
    # note that we set the 400 status explicitly
    logging.error(f"400: {request.url} {e}")
    # if we set headers etc
    return (
        render_template(
            "error.html",
            title="400 Bad Request",
            message="Sorry, your request could not be processed",
        ),
        400,
    )


@app.errorhandler(401)
def unauthorized(e):
    # note that we set the 401 status explicitly
    logging.error(f"401: {request.url} {e}")
    return (
        render_template(
            "error.html",
            title="401 Unauthorized",
            message="Sorry, your request could not be processed",
        ),
        401,
    )


@app.errorhandler(403)
def forbidden(e):
    # note that we set the 403 status explicitly
    logging.error(f"403: {request.url} {e} ")
    return (
        render_template(
            "error.html",
            title="403 Forbidden",
            message="Access to this resource on this server is forbidden",
        ),
        403,
    )


# TODO test if this works with vercel
# Error handler for 413 Payload Too Large
@app.errorhandler(413)
def handle_runtime_error(error):
    # Log the error (optional)
    logging.error("vercel pdf error")
    logging.error(f"Payload Too Large: : {request.url} {error}")

    # Render the custom error page
    return (
        render_template(
            "error.html",
            title="413 Payload Too Large",
            message="use the mirror site"),
        413,
    )


@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    logging.error(f"404: {request.url}")
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_server_error(e):
    # note that we set the 500 status explicitly
    logging.error(f"500: {request.url} {e}")
    return (
        render_template(
            "error.html",
            title="500 Internal Server Error",
            message="Try again later"),
        500,
    )
