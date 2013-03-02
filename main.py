import os, webapp2, jinja2, re
import random, hashlib, hmac
from string import letters
from google.appengine.ext import db
from geopy import geocoders

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

secret = 'ci4@73w94f#jqdi37cw^$94f23d!98w*74f9w7(hf87w7h'

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

class BoardHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		params['user'] = self.user
		return render_str(template, **params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

########User Sign up Code
	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
	return not email or EMAIL_RE.match(email)

class Signup(BoardHandler):
	def get(self):
		self.render("signup.html")

	def post(self):
		have_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(username = self.username,
					  email = self.email)

		if not valid_username(self.username):
			params['error_username'] = "That's not a valid username."
			have_error = True

		if not valid_password(self.password):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		elif self.password != self.verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True

		if not valid_email(self.email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		if have_error:
			self.render('signup.html', **params)
		else:
			self.done()

	def done(self, *a, **kw):
		raise NotImplementedError

#######Register/Sign in
class Register(Signup):
	def done(self):
		#make sure the user doesn't already exist
		u = User.by_name(self.username)
		if u:
			msg = 'That user already exists.'
			self.render('signup.html', error_username = msg)
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()

			self.login(u)
			self.redirect('/')

class Login(BoardHandler):
	def get(self):
		self.render('login.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = User.login(username, password)
		if u:
			self.login(u)
			self.redirect('/')
		else:
			msg = 'Invalid login'
			self.render('login.html', error = msg)

class Logout(BoardHandler):
	def get(self):
		self.logout()
		self.redirect('/signup')


##### user stuff
def make_salt(length = 5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
	return db.Key.from_path('users', group)

class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls, name):
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(),
					name = name,
					pw_hash = pw_hash,
					email = email)

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u

########## Board Stuff

def board_key(name = 'default'):
	return db.Key.from_path('boards', name)

class Pin(db.Model):
	title = db.StringProperty(required = True)
	date = db.StringProperty(required = True)
	location = db.StringProperty(required = True)
	latitude = db.FloatProperty(required = True)
	longitude = db.FloatProperty(required = True)
	description = db.TextProperty(required = True)
	link = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add = True)
	created_by = db.StringProperty(required = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	is_expired = db.BooleanProperty(required = True)
	is_deleted = db.BooleanProperty(required = True)

	def render(self):
		self._render_text = self.description.replace('\n', '<br>')
		return render_str("pin.html", h = self)

class BoardHome(BoardHandler):
	def get(self):
		happinings = db.GqlQuery("SELECT * FROM Pin ORDER BY created DESC LIMIT 10")
		self.render("board-home.html", happinings = happinings)

class PinPage(BoardHandler):
	def get(self, happining_id):
		key = db.Key.from_path('Pin', int(happining_id), parent=board_key())
		happining = db.get(key)

		if not happining:
			self.error(404)
			return

		self.render("permalink.html", happining = happining)

class NewPin(BoardHandler):

	def get(self):
		self.render("new-pin.html")

	def post(self):
		title = self.request.get("title")
		date = self.request.get("date")
		location = self.request.get("location")

		try:
			g = geocoders.Google()
			place, (lat, lng) = g.geocode(location)
			latitude = lat
			longitude = lng
		except:
			error = location + " could not be found on the map."
			latitude = -1.0
			longitude = -1.0


		description = self.request.get("description")
		link = self.request.get("link")
		is_expired = False
		is_deleted = False
		created_by = "Ryan"
		
		if title and description and date and location and (latitude!=-1.0) and (longitude!=-1.0):
			e = Pin(parent = board_key(), title = title, date = date, location = location, latitude=latitude, longitude=longitude, description = description, link = link, created_by = created_by, is_deleted = is_deleted, is_expired = is_expired)
			e.put()
			self.redirect('/%s' % str(e.key().id()))
		elif title and description and date and location:
			self.render("new-pin.html", title=title, date=date, location=location, latitude=latitude, longitude=longitude, description=description, link=link, error = error)
		else:
			error = "You need a title, date, location, and description."
			self.render("new-pin.html", title=title, date=date, location=location, latitude=latitude, longitude=longitude, description=description, link=link, error = error)

class Geo(BoardHandler):
	def get(self):
		self.render("geo.html")

app = webapp2.WSGIApplication([('/?', BoardHome),
							   ('/([0-9]+)', PinPage), 
							   ('/create', NewPin),
							   ('/signup', Register),
							   ('/login', Login),
							   ('/logout', Logout),
							   ('/geo', Geo),
								],
								 debug = True)