#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import re
import os
from string import letters
import jinja2
from google.appengine.ext import db
import urlparse
import utility 
from xml.dom import minidom
import urllib2
import json

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
							   autoescape = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

class BlogHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		return render_str(template, **params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def render_json(self, d):
		json_txt = json.dumps(d)
		self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
		self.write(json_txt)

	def set_secure_cookie(self, name, val):
		cookie_val = utility.make_secure_val(str(val))
		self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (str(name), cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and utility.check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % ('user_id', ''))

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

		if self.request.url.endswith('.json'):
			self.format = 'json'
		else:
			self.format = 'html'



class BaseHandler(webapp2.RequestHandler):
	def render(self, template, **kw):
		self.response.out.write(render_str(template, **kw))

	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

class MainHandler(BaseHandler):
	def get(self):
		visits = 0
		visit_cookie_str = self.request.cookies.get('visits')
		# make sure visits is an int
		if visit_cookie_str:
			cookie_val = utility.check_secure_val(visit_cookie_str)
			if cookie_val:
				visits = int(cookie_val)
				
		
		visits += 1

		new_cookie_val = utility.make_secure_val(str(visits))

		self.response.headers.add_header('Set-Cookie', 'visits=%s' % new_cookie_val)
		
		
		if visits > 1000000:
			message = "You are the best ever!"
		else:
			message = "You've been here %s times!" % visits
		
		
		self.render("main.html", message=message)

class ROT13(BaseHandler):
	def get(self):
		self.render('rot13.html')

	def post(self):
		rot13 = ''
		text = self.request.get('text')
		if text:
			rot13 = text.encode('rot13')

		self.render('rot13.html', text = rot13)

def users_key(group = 'default'):
	return db.Key.from_path('users', group)

class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty(required = False)
	created = db.DateTimeProperty(auto_now_add = True)

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls, name):
		u = User.all().filter('name',name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = utility.make_pw_hash(name, pw)
		return User(parent = users_key(),
					name = name,
					pw_hash = pw_hash,
					email = email)

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and utility.valid_pw(name, pw, u.pw_hash):
			return u

class SignUpHandler(BlogHandler):
	def get(self):
		self.render("signup.html")	

	def valid_username(self, username):
		return USER_RE.match(username)
	
	def valid_password(self, password):
		return PASSWORD_RE.match(password)
	
	def valid_verify(self, password,verify):
		if password == verify and PASSWORD_RE.match(verify) != None:
			return verify
		else:
			return None
	
	def valid_email(email):
		return EMAIL_RE.match(email)
	
	def post(self):
		has_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')
		
		params = dict(username = self.username, 
			email = self.email)

		
		if not USER_RE.match(self.username):
			params['username_error'] = "That is not a valid username"
			has_error = True
		if not PASSWORD_RE.match(self.password):
			params['password_error'] = "That is not a valid password"
			has_error = True
		if not PASSWORD_RE.match(self.verify):
			params['verify_error'] = "That is not a valid password"
			has_error = True
		elif self.password != self.verify:
			params['verify_error'] = "Does not match password"
			has_error = True
		if self.email:
			if not EMAIL_RE.match(self.email):
				params['email_error'] = "Not a valid  email address"
				has_error = True

		if(has_error):
			self.render('signup.html', **params)
		else:

			u = User.by_name(self.username)
			if u:
				msg = 'That user already exists.'
				self.render('signup.html', username_error = msg)
			else:
				u = User.register(self.username, self.password, self.email)
				u.put()
				self.login(u)
				self.redirect('/blog')
		
class WelcomeHandler(BlogHandler):
	def get(self):
		if self.user:
			self.render('welcome.html', username = self.user.name)
		else:
			self.redirect('/signup')
		

class FizzBuzz(BaseHandler):
	def get(self):
		n = self.request.get('n',0)
		if n:
			n = int(n)
		self.render("fizzbuzz.html", n=n)


class ShoppingList(BaseHandler):
	def get(self):
		self.redirect('http://ldcdfoodbiz.appspot.com/')

IP_URL = "http://api.hostip.info/?ip="
def get_coords(ip):
	url = IP_URL + ip
	content = None
	try:
		content = urllib2.urlopen(url).read()
	except URLError:
		return

	if content:
		d = minidom.parseString(content)
		coords = d.getElementsByTagName("gml:coordinates")
		if coords and coords[0].childNodes[0].nodeValue:
			lon, lat = coords[0].childNodes[0].nodeValue.split(',')
			return db.GeoPt(lat, lon)

GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"

def gmaps_img(points):
    ###Your code here
    markers = '&'.join('markers=%s,%s' % (p.lat,p.lon)
    					for p in points)
    return GMAPS_URL + markers

class Art(db.Model):
	title = db.StringProperty(required = True)
	art = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	coords = db.GeoPtProperty(required = False)

class ASCII(BaseHandler):
	def render_front(self, title="", art="", error=""):
		arts = db.GqlQuery("SELECT * FROM Art ORDER BY created DESC")
		
		arts = list(arts)

		points = filter(None, (a.coords for a in arts))

		img_url = None
		if points:
			img_url = gmaps_img(points)

		self.render("ascii.html", title=title, art=art, error=error, arts=arts, img_url = img_url)

	def get(self):
		return self.render_front()

	def post(self):
		title = self.request.get("title")
		art = self.request.get("art")

		if title and art:
			a = Art(title = title, art = art)
			coords = get_coords(self.request.remote_addr)
			if coords:
				a.coords = coords
			a.put()
			self.render_front()
		else:
			error = "We need both a title and some artwork!"
			self.render_front(title=title, art=art, error=error)


def blog_key(name = 'default'):
	return db.Key.from_path('blogs', name)

class Post(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self, ref='/blog/%s' % str(self.key().id()))

	def as_dict(self):
		time_fmt = '%c'
		d = {'subject': self.subject,
			'content': self.content,
			'created': self.created.strftime(time_fmt),
			'last_modified': self.last_modified.strftime(time_fmt)}
		return d

class BlogFront(BlogHandler):
	def get(self):
		posts = greetings = Post.all().order('-created')
		if self.format == 'html':
			self.render('front.html', user = self.user, posts = posts)
		else:
			return self.render_json([p.as_dict() for p in posts])		

class PostPage(BlogHandler):
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)

		if not post:
			self.error(404)
			return
		if self.format == 'html':
			return self.render("permalink.html", post = post, user = self.user)
		else:
			self.render_json(post.as_dict())

class NewPost(BlogHandler):
	def get(self):
		if self.user:
			self.render("newpost.html", user = self.user)
		else:
			self.redirect('/blog')

	def post(self):
		subject = self.request.get('subject')
		content = self.request.get('content')

		if subject and content:
			p = Post(parent = blog_key(), subject = subject, content = content)
			p.put()
			self.redirect('/blog/%s' % str(p.key().id()), user = self.user)
		else:
			error = "subject and content, please!"
			self.render("newpost.html", subject=subject, content=content, error=error, user = self.user)

class Login(BlogHandler):
	def get(self):
		self.render('login.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		user = User.login(username,password)

		if user:
			self.login(user)
			self.redirect('/blog')

		else:
			self.render('login.html', error = "Invalid login.", user = self.user)

class Logout(BlogHandler):
	def get(self):
		self.logout()
		self.redirect('/blog')


app = webapp2.WSGIApplication([
	('/', MainHandler), 
	('/signup', SignUpHandler), 
	('/welcome', WelcomeHandler), 
	('/rot13', ROT13), 
	('/fizzbuzz', FizzBuzz), 
	('/shopping', ShoppingList),
	('/ascii', ASCII),
	('/blog/?(?:\.json)?', BlogFront),
	('/newpost', NewPost),
	('/blog/([0-9]+)(?:\.json)?', PostPage),
	('/login', Login),
	('/logout', Logout)
	], debug=True)
