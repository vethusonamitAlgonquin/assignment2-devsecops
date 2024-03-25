from flask import Flask, redirect, url_for, session, request, jsonify
from flask_oauthlib.client import OAuth
import requests, logging, logging.handlers

#app name
logapp = {'app_name':'Google SSO App'}
app = Flask(__name__)
app.secret_key = '"testingtesting'

# logging
app.logger.setLevel(logging.INFO)
handler = logging.handlers.SysLogHandler(address = ('192.168.75.133', 514)) #add vm ip here
formatter = logging.Formatter('%(asctime)s %(app_name)s : %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)
app.logger = logging.LoggerAdapter(app.logger,logapp)
# Google sso id
google_client_id ='CLIENT_ID'
google_client_secret = 'CLIENT_SECRET'
google_redirect_uri = 'http://localhost:8000/login/authorized'

oauth = OAuth(app)
google = oauth.remote_app(
    'google',
    consumer_key=google_client_id,
    consumer_secret=google_client_secret,
    request_token_params={
        'scope': 'email',
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)

@app.route('/')
def index():
    if 'google_token' in session:
        me = google.get('userinfo')
        data = me.data
        app.logger.info(f'{data["email"]} is logging in')
        return f'Hello {data["email"]}! <a href="/logout">Logout</a>'
    
    app.logger.info('User is not logged in')
    return 'Hello! Log in with your Google account: <a href="/login">Log in</a>'

@app.route('/login')
def login():
    app.logger.info('User is trying to log in with Google account')
    return google.authorize(callback=url_for('authorized', _external=True))

@app.route('/login/authorized')
def authorized():
    response = google.authorized_response()
    if response is None or response.get('access_token') is None:
        app.logger.info('User denied the request to sign in.')
        return 'Login failed.'

    session['google_token'] = (response['access_token'], '')
    me = google.get('userinfo')
    # Here, 'me.data' contains user information.
    # You can perform registration process using this information if needed.
    app.logger.info(f'{me.data["email"]} is logged in')
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('google_token', None)
    app.logger.info('User is logged out')
    return redirect(url_for('index'))

#@oauth.tokengetter
#def get_google_oauth_token():
#    return session.get('google_token')
@google.tokengetter
def get_google_oauth_token():
    app.logger.info(f'{session} is the google token')
    return session.get('google_token')


if __name__ == '__main__':
    app.run(debug=True)