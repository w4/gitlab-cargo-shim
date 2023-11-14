# Creates a personal access token using the GitLab UI, given only a username + password combination. This is required
# when using the spawned instance of GitLab in smoke tests, as we only get back a password from the logs, and there's
# no way for us to authenticate with the GitLab API using just a password.
#
# Adapted from https://gist.github.com/gpocentek/bd4c3fbf8a6ce226ebddc4aad6b46c0a

import re
import sys
import os
import requests
import bs4

BASE_URL = "http://127.0.0.1"
SIGN_IN_URL = BASE_URL + "/users/sign_in"
PAT_URL = BASE_URL + "/-/profile/personal_access_tokens"

session = requests.Session()

# fetch CSRF for sign-in page
print('Fetching CSRF token from sign in page', file=sys.stderr)
sign_in_page = session.get(SIGN_IN_URL)
root = bs4.BeautifulSoup(sign_in_page.text, "html5lib")
csrf = root.find_all("meta", attrs={'name': 'csrf-token'})[0]['content']

if not csrf:
    print('Unable to find csrf token on sign in page', file=sys.stderr)
    sys.exit(1)

# login to gitlab using the ROOT_PASSWORD env var, storing the session token in our session object
sign_in_res = session.post(SIGN_IN_URL, data={
    'user[login]': 'root',
    'user[password]': os.environ['ROOT_PASSWORD'].strip(),
    'authenticity_token': csrf,
})

if sign_in_res.status_code != 200:
    print('Failed to login to GitLab instance', file=sys.stderr)
    sys.exit(1)

print('Successfully logged into GitLab, fetching CSRF token for PAT page', file=sys.stderr)

# fetch the csrf token for PAT creation
pat_page = session.get(PAT_URL)
root = bs4.BeautifulSoup(pat_page.text, "html5lib")
csrf = root.find_all("meta", attrs={'name': 'csrf-token'})[0]['content']

if not csrf:
    print('Unable to find csrf token on PAT creation page', file=sys.stderr)
    sys.exit(1)

print('Found CSRF token, creating PAT', file=sys.stderr)

# create the personal access token
response = session.post(PAT_URL, data={
    "personal_access_token[name]": "apitoken",
    "personal_access_token[scopes][]": "api",
    "authenticity_token": csrf,
})

personal_access_token = response.json()['new_token']
if not personal_access_token:
    print('Failed to find personal access token in response', file=sys.stderr)
    sys.exit(1)

print(personal_access_token)
