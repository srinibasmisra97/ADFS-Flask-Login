import requests
from flask import Flask, session, redirect, request
from flask.json import jsonify
from requests_oauthlib import OAuth2Session
from settings import *

app = Flask(__name__)
app.secret_key = "abcdefghi" # Secret key required for Flask session


@app.route("/", methods=['GET'])
def root():
    if 'logged_in' not in session:
        session['logged_in'] = False
    
    return jsonify({
        "logged_in": session['logged_in'],
        "user": session['user'] if "user" in session else {}
    })


@app.route("/signin", methods=['GET'])
def signin():
    if 'logged_in' not in session:
        session['logged_in'] = False
    
    adfs = OAuth2Session(ADFS_CLIENT_ID, scope="openid profile", redirect_uri=ADFS_REDIRECT_URI)
    authorization_url, state = adfs.authorization_url("{0}{1}".format(ADFS_AUTHORITY, ADFS_AUTHORIZE_ENDPOINT))
    session['oauth_state'] = state

    return redirect(authorization_url)


@app.route("/callback", methods=['GET'])
def callback():
    print(request.full_path)
    expected_state = session['oauth_state']
    adfs = OAuth2Session(ADFS_CLIENT_ID, state=expected_state, scope="openid profile", redirect_uri=ADFS_REDIRECT_URI)
    token = adfs.fetch_token(
        "{0}{1}".format(ADFS_AUTHORITY, ADFS_TOKEN_ENDPOINT),
        client_secret=ADFS_CLIENT_SECRET,
        authorization_response=request.full_path
    )

    profile_info_response = requests.post(
        url=ADFS_PROFILE_INFO,
        headers={
            'Authorization': 'Bearer ' + token['access_token']
        }
    )

    session['user'] = profile_info_response.json()
    session['logged_in'] = True

    return redirect("/")


@app.route("/signout", methods=['GET'])
def signout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run()