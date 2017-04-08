import os
import re
import hmac
import jinja2
import hashlib
import random

from string import letters
from google.appengine.ext import db

# Configure jinja2
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir), autoescape=True)

#### GLOBAL FUNCTIONS ####


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

""" MODEL KEYS """


def blog_key(name="default"):
    # function responsibility is to create ancestor for all Blog Posts
    return db.Key.from_path('blogs', name)


def users_key(group='default'):
    # function responsibility is to create ancestor for all Users
    return db.Key.from_path('users', group)


""" USER VALIDATION """


def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)


def valid_password(password):
    PASS_RE = re.compile(r"^.{3,20}$")
    return password and PASS_RE.match(password)


def valid_email(email):
    EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
    return not email or EMAIL_RE.match(email)


""" Authentication/Registration """
SECRET = "743ls029;afjkdls;a934293829*@*(@&)"


def make_pw_hash(name, pw, salt=None):
    # function is responsible for creating a pw hash with sha256 algorithm
    # format salt,Hash
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def make_salt(length=5):
    # function is responsible for creating salt for passwords
    return ''.join(random.choice(letters) for x in xrange(length))


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def make_secure_val(val):
    # function is responsible for creating a secure_hash in format: val|hashlib
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())


def check_secure_val(secure_val):
    # function is responsible for validating hash
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val
