from hashlib import sha256
import hmac
import json
import os
import threading
import urlparse

from dropbox import DropboxOAuth2Flow, oauth

from flask import abort, Flask, redirect, render_template, request, session, url_for
from markdown import markdown
import redis
import dropbox



redis_url = os.environ['REDISTOGO_URL']
redis_client = redis.from_url(redis_url)

# App key and secret from the App console (dropbox.com/developers/apps)
APP_KEY = os.environ['APP_KEY']
APP_SECRET = os.environ['APP_SECRET']


app = Flask(__name__)
app.debug = True

# A random secret used by Flask to encrypt session data cookies
app.secret_key = os.environ['FLASK_SECRET_KEY']

def get_url(route):
	'''Generate a proper URL, forcing HTTPS if not running locally'''
	host = urlparse.urlparse(request.url).hostname
	url = url_for(
		route,
		_external=True,
		_scheme='http' if host in ('127.0.0.1', 'localhost') else 'https'
	)
	print url
	return url




def get_flow():
    return DropboxOAuth2Flow(
        APP_KEY, APP_SECRET, get_url('oauth_callback'), session,
        "dropbox-auth-csrf-token")


@app.route('/welcome')
def welcome():
	return render_template('welcome.html', redirect_url=get_url('oauth_callback'),
	                       webhook_url=get_url('webhook'), home_url=get_url('index'), app_key=APP_KEY)




# URL handler for /dropbox-auth-finish
@app.route('/oauth_callback')
def oauth_callback():
	# try:
	oauth_result = get_flow().finish(request.args)
	print oauth_result

	redis_client.hset('tokens', oauth_result.account_id,  oauth_result.access_token)

	process_user(oauth_result.account_id)

	return redirect(url_for('done'))

    # except oauth.BadRequestException, e:
    #     print e
    # except oauth.BadStateException, e:
    #     # Start the auth flow again.
    #     redirect("/dropbox-auth-start")
    # except oauth.CsrfException, e:
    #     http_status(403)
    # except oauth.NotApprovedException, e:
    #     flash('Not approved?  Why not?')
    #     return redirect_to("/home")
    # except oauth.ProviderException, e:
    #     logger.log("Auth error: %s" % (e,))
    #     http_status(403)





def process_user(account):
	'''Call /files/list_folder for the given user ID and process any changes.'''

	# OAuth token for the user
	token = redis_client.hget('tokens', account)

	# cursor for the user (None the first time)
	cursor = redis_client.hget('cursors', account)

	dbx = dropbox.Dropbox(token)
	has_more = True

	while has_more:
		if cursor is None:
			result = dbx.files_list_folder(path='')
		else:
			result = dbx.files_list_folder_continue(cursor)

		for entry in result.entries:

			# Ignore deleted files, folders, and non-markdown files
			if (isinstance(entry, dropbox.files.DeletedMetadata) or
				    isinstance(entry, dropbox.files.FolderMetadata) or
				    not entry.path_lower.endswith('.md')):
				continue

			# Convert to Markdown and store as <basename>.html
			_, resp = dbx.files_download(entry.path_lower)
			html = markdown(resp.content)
			f = open('html1.html', 'w')
			f.write(html.encode('utf8'))
			f.close()

			with open('html1.html', "rb") as f:
				dbx.files_upload(f.read(), entry.path_lower[:-3] + '.html', mode=dropbox.files.WriteMode('overwrite'))


		# Update cursor
		cursor = result.cursor
		redis_client.hset('cursors', account, cursor)

		# Repeat only if there's more to do
		has_more = result.has_more


@app.route('/')
def index():
	return render_template('index.html')



# URL handler for /dropbox-auth-start
@app.route('/login')
def login():

	authorize_url = get_flow().start()
	return redirect(authorize_url)




@app.route('/done')
def done():
	return render_template('done.html')


def validate_request():
	'''Validate that the request is properly signed by Dropbox.
       (If not, this is a spoofed webhook.)'''

	signature = request.headers.get('X-Dropbox-Signature')
	return signature == hmac.new(APP_SECRET, request.data, sha256).hexdigest()


@app.route('/webhook', methods=['GET'])
def verify():
	'''Respond to the webhook verification (GET request) by echoing back the challenge parameter.'''

	return request.args.get('challenge')


def validate_request():
    '''Validate that the request is properly signed by Dropbox.
       (If not, this is a spoofed webhook.)'''

    signature = request.headers.get('X-Dropbox-Signature')
    print signature
    return signature == hmac.new(APP_SECRET, request.data, sha256).hexdigest()

@app.route('/webhook', methods=['POST'])
def webhook():
	'''Receive a list of changed user IDs from Dropbox and process each.'''

	# Make sure this is a valid request from Dropbox
	# Make sure this is a valid request from Dropbox
	if not validate_request(): abort(403)


	for account in json.loads(request.data)['list_folder']['accounts']:
		print account
		# We need to respond quickly to the webhook request, so we do the
		# actual work in a separate thread. For more robustness, it's a
		# good idea to add the work to a reliable queue and process the queue
		# in a worker process.
		threading.Thread(target=process_user, args=(account,)).start()
	return ''


if __name__ == '__main__':
	app.run(debug=True)