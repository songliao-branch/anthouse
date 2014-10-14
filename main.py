
import os 
import re
import jinja2
import webapp2
import cgi 
from google.appengine.ext import db
from string import letters
import time
import datetime
import hashlib
import hmac
import random
import string
import urllib2
import json
from xml.dom import minidom
import logging

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
    autoescape =True)


Secret="secre-`11kdk`1-3opjdvkldfnl05"
#return a hash string, usually very long
def hash_str(s):
    #return hashlib.md5(s).hexdigest()
    return hmac.new(Secret,s).hexdigest()

#return a format of 's|hash string'
def make_secure_val(val):
    return "%s|%s"% (val,hmac.new(Secret,val).hexdigest())

#decode, h is the full format of 's|hash string'
def check_secure_val(h):
    #value is the s
    val = h.split('|')[0]
    #if the full input is equal to verified hash string
    if h == make_secure_val(val):
        return val

def escape_html(s):
    return cgi.escape(s,quote= True)

class Handler(webapp2.RequestHandler):
    def write(self,*a,**kw):
        self.response.out.write(*a,**kw)
    def render_str(self,template,**params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self,template,**kw):
        self.write(self.render_str(template,**kw))


    def set_user_cookie(self,user):#set the cookie from the input to Set-Cookie
        hasheduser = make_secure_val(str(user.key().id()))
        self.response.headers.add_header('Set-Cookie','user_id=%s;Path=/'%hasheduser)
        self.redirect("/welcome")

    def render_json(self,d):
        jtxt=json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        
        self.write(jtxt)


class MainPage(Handler):
    def get(self):

        self.response.headers['Content-Type']='text/plain'

        visits=0
        visit_cookie_str=self.request.cookies.get('visits')
        #self.write("visit cookie string is " + visit_cookie_str)
        if visit_cookie_str: 
            cookie_value = check_secure_val(visit_cookie_str)
            if cookie_value:
                visits=int(cookie_value)

        visits+=1

        new_cookie_value= make_secure_val(str(visits))

        self.response.headers.add_header('Set-Cookie','visits=%s'%new_cookie_value)
        self.write('You have been here %s times' %visits)

  
class FizzBuzzHandler(Handler):
    def get(self):
        n = self.request.get('n',0)
        n = n and int(n)
        self.render('fizzbuzz.html',n=n)

IP_URL = "http://api.hostip.info/?ip="
def get_coords(ip):
    ip = "23.24.209.141"
    url = IP_URL + ip
    content = None

    try:
        content = urllib2.urlopen(url).read()
    except URLError:
        return

    if content:
        #parse xml and find the coordinates
        doc = minidom.parseString(content)
        coords = doc.getElementsByTagName('gml:coordinates')
        if coords and coords[0].firstChild.data:
            lon,lat= coords[0].firstChild.data.split(',')
            return db.GeoPt(lat,lon)

GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"


def markers(points):
    markers='&'.join('markers=%s,%s'%(p.lat,p.lon)
     for p in points)
    return markers

class Art(db.Model):#a table/entity defined in google datastore
    title = db.StringProperty(required = True)
    art = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    coords = db.GeoPtProperty()

CACHE = {}

def top_arts(update = False):
    key = 'top'
    #if update is false
    if not update and key in CACHE:#cache hit, doesn't need to run query

        arts = CACHE[key]

    else:#cache miss
        logging.error("DB query")
        arts = db.GqlQuery("SELECT * FROM Art ORDER BY created DESC")
        arts = list(arts)
        CACHE[key]=arts

    return arts


class AsciichanHandler(Handler):
    def render_chan(self,title="",art="",error=""):
        #self.render("Asciichan.html",title=title,art=art,error=error)
        arts = db.GqlQuery("SELECT * FROM Art ORDER BY created DESC")
        arts = list(arts)

        #arts = top_arts()

        image_url=None

        points = filter(None,(a.coords for a in arts))
        if points:
            image_url=GMAPS_URL+markers(points)

        self.render("Asciichan.html",title=title,art=art,error=error,arts=arts,image_url=image_url)

    def get(self):
        #self.write(repr(get_coords(self.request.remote_addr)))
        self.render_chan()

    def post(self):
        title = self.request.get("title")
        art = self.request.get("art")
        if title and art:
            a=Art(title=title,art=art)
            #look up the user's coordinates from their ip
            coords = get_coords(self.request.remote_addr)
            if coords:
                a.coords=coords

            a.put()#store in the database
            #CACHE.clear()
            #it's better to overwrite with new ones instead of clearing cache
            time.sleep(.01)

            #top_arts(True)

            #consistency issue, the put function takes time and we are spontaenously rendering the new page
            #so we have to let the sytem sleep one second


            self.redirect('/asciichan')
        else:
            error="yeah..we need both a title and an art"
            self.render_chan(title,art,error=error)

"""====HW3 BUILD A SIMPLE BLOG======
====== Sept 20,2014
======"""    

#hw3:build a simple blog   

class Blog(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required =True)
    created = db.DateTimeProperty(auto_now_add = True)


    def render(self):
        #self._render_text = self.content.replace('\n', '<br>')
        return render_str("blog.html",blogs=self)

    def as_dict(self):
        time_format='%c'
        dic = {
        'subject': self.subject,
        'content':self.content,
        'created':self.created.strftime(time_format)
        }
        return dic

def blog_key(name='default'):
    return db.Key.from_path('blogs',name)

class BlogHandler(Handler):
    def render_blog(self,subject=""):
        blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC limit 15")
        self.render("blog.html",blogs=blogs)

    def get(self):
        #self.render_blog()

        blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC limit 15")

        if self.request.url.endswith('.json'):
            self.format = 'json'
            return self.render_json([blog.as_dict() for blog in blogs])

        else:
            self.format = 'html'
            self.render("blog.html",blogs=blogs)

class NewLinkHandler(Handler):
    def get(self,blog_id):
        matched_blog = Blog.get_by_id(int(blog_id))#get the blog with the matched id
        if matched_blog:
            self.render("NewLink.html",blog = matched_blog)
        else:
            self.write("This link does not exist")


class NewPostHandler(Handler):
    def get(self):
        self.render("newpost.html")
        
    def post(self):
        
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            newblog=Blog(subject=subject,content=content)
            newblog_key = newblog.put()
            self.redirect('/blog/%d' % newblog_key.id())
            #now generate json data for the new blog
            
        else:
            error = "Please don't leave your memories blank"
            self.render("newpost.html",subject=subject,content=content,error=error)


def users_key(group = 'default'):
    return db.Key.from_path('users', group)

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name,pw,salt=None):
    if not salt:
        salt = make_salt()
    h=hashlib.sha256(name+pw+salt).hexdigest()
    return "%s|%s" %(h,salt)

def valid_pw(name,pw,h):
    salt = h.split('|')[1]
    return h == make_pw_hash(name,pw,salt)

class User(db.Model):
    username = db.StringProperty(required = True)
    #store a hashed_password instead
    password = db.StringProperty(required =True)

    email = db.StringProperty(required=False)

    # @classmethod
    # def by_id(cls,uid):
    #     return User.get_by_id(uid, parent = users_key())

    # @classmethod
    # def by_name(cls,name):
    #     u = Users.all().filter('name = ', name).get()

    # @classmethod
    # def register(cls,name,pw,email=None):
    #     pw_hash=make_pw_hash(name,pw)
    #     return User(parent= users_key(),
    #         name=name,
    #         password=pw_hash,
    #         email=email)

    # @classmethod
    # def login(cls, name, pw):
    #     u = cls.by_name(name)
    #     if u and valid_pw(name, pw, u.pw_hash):
    #         return u

class SignUpHandler(Handler):
    def get(self):

        self.render("signup.html")


    def post(self):


        getusername = escape_html(self.request.get('username'))
        getpassword = escape_html(self.request.get('password'))
        getverify = escape_html(self.request.get('verify'))
        getemail = escape_html(self.request.get('email'))

        correct = True
        usernameErrMsg=""
        passwordErrMsg=""
        verifyErrMsg=""
        emailErrMsg=""

        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        PASS_RE = re.compile(r"^.{3,20}$")
        EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")

        user_id_formatted_cookie = self.request.cookies.get('user_id')
        #user enters a username, check if it is in the database and the cookie

        #all_users = db.GqlQuery("SELECT * FROM User")


        u = User.all().filter('username =',getusername).get()

        if u:
            usernameErrMsg="Username not available"
            getusername=""
            correct=False

        # if all_users:
        #     for eachuser in all_users:
        #         # self.write(str(eachuser.username))
        #         # self.response.out.write("\n")
        #         if getusername==eachuser.username:
        #             usernameErrMsg="Username not available"
        #             getusername=""
        #             correct=False

        # elif user_id_formatted_cookie:
        #     userid = check_secure_val(user_id_formatted_cookie)
        #     if userid:
                
        #         matched_user= User.get_by_id(int(userid))
        #         matched_username = str(matched_user.username)
        #         #
        #         if getusername==matched_username:
        #             usernameErrMsg="User already exists"
        #             getusername=""
        #             correct=False

        elif (not getusername) or "  " in getusername or not USER_RE.match(getusername):
            usernameErrMsg ="Please enter a valid user name"
            getusername = ""
            correct=False

        if not getpassword or not PASS_RE.match(getpassword):
            passwordErrMsg = "Please enter a password"
            correct=False
        if not getverify:
            verifyErrMsg = "Please retype yoru password"
            correct=False
        elif getpassword != getverify:

            verifyErrMsg = "Password are not the same"
            correct=False

        if getemail:
            if not EMAIL_REGEX.match(getemail):
                emailErrMsg = "Please enter a vaid email address"
                getemail = ""
                correct= False
        if not correct:
            self.render("signup.html",username=getusername,password="",verify="",email=getemail,
                uerror=usernameErrMsg,perror=passwordErrMsg,verror=verifyErrMsg,eerror=emailErrMsg)
        else:
            #hashed the password 

            hash_password= make_pw_hash(getusername,getpassword)

            u = User(username=getusername,password=hash_password,email=getemail)
            u.put()

            #rewrite this
            self.set_user_cookie(u)
            # hashed_user = make_secure_val(str(u.key().id()))
            # self.response.headers.add_header('Set-Cookie','user_id=%s;Path=/'%hashed_user)
            # self.redirect("/welcome")

class WelcomeHandler(Handler):
    def get(self):
        #retrive the id from the cookie
        user_id_formatted_cookie = self.request.cookies.get('user_id')
        if user_id_formatted_cookie:
            #userid return id if checked, else return None
            userid = check_secure_val(user_id_formatted_cookie)

            if userid:
                matched_user= User.get_by_id(int(userid))
                getusername = str(matched_user.username)
                self.render("welcome.html",username=getusername)
                #self.write("get username is "+ getusername)
            else:
                #time.sleep(3)
                #self.write("Please sign up, will be direct to signup page in 3 seconds")
                
                self.redirect('/signup')
        else:
            self.redirect('/signup')

class LoginHandler(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        getusername = self.request.get("username")
        getpassword = self.request.get("password")
        #when user enters a password, it matches the database
        
        u = User.all().filter('username =',getusername).get()
        if u and valid_pw(getusername,getpassword,u.password):
            self.render("welcome.html",username=getusername)
            
            self.set_user_cookie(u)

        else:
            error="Invalid login"
            self.render('login.html',error=error)

COOKIE_RE = re.compile(r'.+=;\s*Path=/')
def valid_cookie(cookie):
    return cookie and COOKIE_RE.match(cookie)

class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/'%'')
        self.redirect('/signup')
    def post(self):
        pass

# class BlogJsonHandler(Handler):
#     def get(self):
#         #first should get all the blogs, without run the query
#         self.response.headers['Content-Type']='application/json; charset=UTF-8'
#         blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC limit 15")
#         self.write('[')
#         for blog in blogs:
#             self.write(json.dumps([{'content':'%s'},{'created':'%s'},{'last-modified':'%s'},{'subject':'%s'}])%(blog.content,blog.created,blog.created,blog.subject))
       
#         self.write(']')

# class NewLinkJsonHandler(Handler):
#     def get(self,blog_id):
#         #first should get all the blogs, without run the query
#         self.response.headers['Content-Type']='application/json; charset=UTF-8'
#         blog = Blog.get_by_id(int(blog_id))

#         self.write('[')
        
#         self.write(json.dumps([{'content':'%s'},{'created':'%s'},{'last-modified':'%s'},{'subject':'%s'}])%(blog.content,blog.created,blog.created,blog.subject))
       
#         self.write(']')      



app = webapp2.WSGIApplication([('/', MainPage),
    ('/fizzbuzz',FizzBuzzHandler),
    ('/asciichan',AsciichanHandler),
    ('/blog/?(?:.json)?',BlogHandler),
    ('/blog/newpost',NewPostHandler),
    ('/blog/(\d+)',NewLinkHandler),
    ('/signup/?',SignUpHandler),
    ('/welcome/?',WelcomeHandler),
    ('/login/?',LoginHandler),
    ('/logout/?',LogoutHandler),
    #('/blog(?:.json)?',BlogJsonHandler),
    #('/blog/(\d+)(?:.json)?',NewLinkJsonHandler)
    ], debug=True)
