from urllib.parse import urlparse
import os

from flask import Blueprint, request, redirect, session
from flask_login import logout_user
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from web.views.helpers import prevent_csrf, get_fame_url
from web.auth.saml.user_management import authenticate
from web.views.negotiation import safe_redirect_target

auth = Blueprint("auth", __name__, template_folder="templates")


def create_user(user):
    user.save()
    user.generate_avatar()

    return True


def init_saml_auth(req):
    saml_auth = OneLogin_Saml2_Auth(
        req,
        custom_base_path=os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "saml/config"
        ),
    )
    return saml_auth


def prepare_auth_request(request):
    fame_url = urlparse(get_fame_url())
    return {
        "https": "on" if fame_url.scheme == "https" else "off",
        "http_host": fame_url.netloc,
        "server_port": fame_url.port,
        "script_name": request.path,
        "get_data": request.args.copy(),
        "post_data": request.form.copy(),
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        "query_string": request.query_string,
    }


@auth.route("/saml/acs", methods=["GET", "POST"])
def acs():
    req = prepare_auth_request(request)
    saml_auth = init_saml_auth(req)
    saml_auth.process_response()
    errors = saml_auth.get_errors()

    if len(errors) == 0:  # No errors, let's authenticate the user
        relay_state = request.form.get("RelayState")
        expected_relay_state = session.pop("saml_relay_state", None)
        redir = session.pop("saml_redirect", "/")
        if not expected_relay_state or relay_state != expected_relay_state:
            return redirect("/")

        session["samlUserdata"] = saml_auth.get_attributes()
        session["samlNameId"] = saml_auth.get_nameid()
        session["samlSessionIndex"] = saml_auth.get_session_index()
        authenticate(session)

        return redirect(safe_redirect_target(redir))


@auth.route("/saml-login", methods=["GET", "POST"])
@prevent_csrf
def login():
    req = prepare_auth_request(request)
    saml_auth = init_saml_auth(req)

    redir = safe_redirect_target(request.args.get("next"))

    if "/login" in redir:
        redir = "/"

    relay_state = OneLogin_Saml2_Utils.generate_unique_id()
    session["saml_relay_state"] = relay_state
    session["saml_redirect"] = redir

    return redirect(saml_auth.login(relay_state))


@auth.route("/logout")
def logout():
    req = prepare_auth_request(request)
    saml_auth = init_saml_auth(req)
    logout_user()
    return redirect(
        saml_auth.logout(
            return_to=get_fame_url(),
            name_id=session["samlNameId"],
            session_index=session["samlSessionIndex"],
        )
    )
