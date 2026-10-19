"""Minimal dashboard frontend for the NIDS API.

Serves a single HTML page together with its CSS and JavaScript. The page
fetches the read-only JSON endpoints exposed by :mod:`nids.api`; it performs no
backend logic and never starts packet capture.
"""

from pathlib import Path

from flask import Blueprint, render_template

WEB_ROOT = Path(__file__).resolve().parent

web = Blueprint(
    "web",
    __name__,
    template_folder=str(WEB_ROOT / "templates"),
    static_folder=str(WEB_ROOT / "static"),
    static_url_path="/static",
)


@web.get("/")
def dashboard():
    return render_template("index.html")


@web.get("/live")
def live():
    return render_template("live.html")


def register_web(app):
    """Attach the dashboard routes to a Flask application."""
    app.register_blueprint(web)
    return app
