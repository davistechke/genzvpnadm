import logging

import click
from flask import Flask, render_template

from config import Config
from models import Admin, db


def create_app(overrides=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if overrides:
        app.config.update(overrides)
    logging.basicConfig(level=logging.INFO)
    db.init_app(app)

    from routes import admin, api, web
    from routes.common import csrf_token
    for m in (web, admin, api):
        app.register_blueprint(m.bp)

    @app.context_processor
    def inject():
        return {"csrf_token": csrf_token}

    @app.template_filter("flag")
    def flag(code):
        code = (code or "").upper()
        return "".join(chr(0x1F1E6 + ord(c) - 65) for c in code) if len(code) == 2 and code.isalpha() else ""

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; img-src 'self' data:; script-src 'self'")
        if not resp.headers.get("Cache-Control"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(413)
    def oops(e):
        return render_template("error.html", code=e.code, message=getattr(e, "description", "")), e.code

    with app.app_context():
        db.create_all()
        email, pw = app.config["ADMIN_EMAIL"].strip().lower(), app.config["ADMIN_PASSWORD"]
        if email and pw and not Admin.query.filter_by(email=email).first():
            a = Admin(email=email)
            a.set_password(pw)
            db.session.add(a)
            db.session.commit()
        if app.config["SEED_DEFAULT_TWEAK"]:
            from services.defaults import seed_default_tweak
            seed_default_tweak()

    @app.cli.command("create-admin")
    @click.argument("email")
    @click.password_option()
    def create_admin(email, password):
        email = email.strip().lower()
        a = Admin.query.filter_by(email=email).first() or Admin(email=email)
        a.set_password(password)
        db.session.add(a)
        db.session.commit()
        click.echo(f"Admin ready: {email}. Sign in at /admin")

    return app
