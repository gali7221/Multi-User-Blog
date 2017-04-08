import webapp2
import time
from utils import *


#### Handlers ####
class BlogHandler(webapp2.RequestHandler):
    """ Handler will be main handler that all other handlers inherit from """

    ### TEMPLATING ###
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    ### COOKIES ###
    def set_secure_cookie(self, name, val):
        """ function is responsible for setting a cookie header set name equal to cookie_val """
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """ function is responsible for requesting cookie through name argument returns true if valid cookie_val """
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


class BlogFront(BlogHandler):
    """ handler will take care of front page when user visits page """

    def get(self):
        posts = db.GqlQuery(
            "Select * from Post order by created desc limit 10")
        self.render("front.html", posts=posts)


class PostPage(BlogHandler):
    """ Handler will be responsible for individual post pages """

    def get(self, post_id):
        """ post_id refers to the regex expression at the end of the postpage routing """
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        # comments = Comment.all().filter("post=", post.key().id())
        if not self.user:
            self.redirect('/login')

        elif not post:
            self.error(404)
            return
        else:
            self.render('permalink.html', post=post)


class NewPost(BlogHandler):
    """ handler will be responsible for creating and validating new posts """

    def get(self):
        if self.user:
            self.render('newpost.html')
        else:
            self.redirect('/login')
        # self.render('newpost.html')

    def post(self):
        """ function is responsible for validating subject and content and storing into datastore """
        if not self.user:  # check if user is logged-in
            # if not - direct unlogged user to home page
            self.redirect('/blog')

        # requests from name='subject' attribute on form
        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.request.get('author')

        if subject and content:
            # turn into post object
            p = Post(parent=blog_key(), subject=subject,
                     content=content, author=author, likes=0, liked_by=[])
            p.put()  # store into datastore
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "Subject and content are required."
            self.render('newpost.html', subject=subject,
                        content=content, error=error)


class Signup(BlogHandler):
    """ class is responsible for validating users name, password, verify and/or email """

    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

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


class Register(Signup):
    """ function is responsible for registering users """

    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


class Login(BlogHandler):
    """ function is responsible for logging-in users """

    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login.html', error=msg)


class Logout(BlogHandler):
    """ function is responsible for logging out users """

    def get(self):
        self.logout()
        self.redirect('/login')


#### NEW FEATURES ####
class RemovePost(BlogHandler):
    """ class is responsible for handling delete posts for only authors """

    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            author = post.author

            if post is not None and author == self.user.name:
                post.delete()
                time.sleep(0.2)
                self.redirect('/blog')
            else:
                self.redirect('/blog')


class EditPost(BlogHandler):
    """ class is responsible for handling editing posts authors of blog posts """

    def get(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            author = post.author

            if post is not None:
                # post exists
                if author == self.user.name:
                    self.render("edit.html", subject=post.subject,
                                content=post.content)
                else:
                    self.redirect('/blog/%s' % str(post.key().id()))

    def post(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            # remember to retrieve key before, otherwise you will be rewriting
            # it!
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            # prepend with post so you will access the present post subject and
            # content
            post.subject = self.request.get('subject')
            post.content = self.request.get('content')

            if post.subject and post.content:
                # ignore value by put(). key will not change when you update.
                post.put()
                self.redirect('/blog/%s' % str(post.key().id()))
            else:
                error = 'Remember that both subject and content are required.'
                self.render('edit.html', subject=subject,
                            content=content, error=error)


class LikePost(BlogHandler):
    """ class is responsible for allowing users to like foreign posts """

    def get(self, post_id):
        if not self.user:
            self.redirect("/login")
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            author = post.author
            logged_user = self.user.name

            if post is not None:
                if author == self.user.name or logged_user in post.liked_by:
                    self.redirect('/error')
                else:
                    # post exists..
                    post.likes += 1
                    post.liked_by.append(self.user.name)

                    post.put()
                    time.sleep(0.2)
                    self.redirect('/blog/%s' % str(post.key().id()))


class PostComment(BlogHandler):
    """ class is responsible for creating a new post. """

    def get(self, post_id):
        if not self.user:
            return self.redirect("/login")

        post = Post.get_by_id(int(post_id), parent=blog_key())
        subject = post.subject
        content = post.content
        self.render("newcomment.html", subject=subject,
                    content=content, pkey=post.key())

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        content = self.request.get('content')
        if not post:
            self.error(404)
            return

        if not self.user:
            self.redirect('/login')

        comment = self.request.get('comment')

        if comment:
            c = Comment(comment=comment, post=post_id,
                        parent=self.user.key())
            c.put()
            self.redirect('/blog/%s' % str(post_id))
        else:
            error = "please provide a comment!"
            self.render("permalink.html", post=post,
                        content=content, error=error)


class EditComment(BlogHandler):
    """ class is responsible for editing comment posts by author """

    def get(self, post_id, comment_id):
        if not self.user:
            self.redirect('/login')

        post = Post.get_by_id(int(post_id), parent=blog_key())
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment and post is not None:
            self.render("editcomment.html", subject=post.subject,
                        content=post.content, comment=comment.comment)

    def post(self, post_id, comment_id):
        if not self.user:
            self.redirect('/login')

        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        if comment.parent().key().id() == self.user.key().id():
            comment.comment = self.request.get('comment')
            comment.put()
        self.redirect('/blog/%s' % str(post_id))


class DeleteComment(BlogHandler):
    """ class is responsible for deleting comment posts """

    def get(self, post_id, comment_id):
        if not self.user:
            self.redirect('/login')

        post = Post.get_by_id(int(post_id), parent=blog_key())
        comment = Comment.get_by_id(int(comment_id), parent=self.user.key())
        author = post.author

        if comment and post is not None:
            if author == self.user.name:
                comment.delete()
                self.redirect('/blog/%s' % str(post_id))

#### MODELS ####


class Post(db.Model):
    """model class will be in control of all parts of a post and what are required. """
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    # new feature to allow only authors to edit/delete posts
    author = db.StringProperty(required=True)
    likes = db.IntegerProperty(required=True)
    liked_by = db.ListProperty(str)

    # render function will be responsible for display of posts
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    @property
    def comments(self):
        return Comment.all().filter("post = ", str(self.key().id()))


class User(db.Model):
    """ model is responsible for creating user parts """
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


#### NEW FEATURES ####
class Comment(db.Model):
    comment = db.TextProperty(required=True)
    post = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


# Configure Routing
app = webapp2.WSGIApplication([
    ('/', BlogFront),
    ('/blog', BlogFront),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/newpost', NewPost),
    ('/blog/([0-9]+)/removepost', RemovePost),
    ('/blog/([0-9]+)/edit', EditPost),
    ('/blog/([0-9]+)/like', LikePost),
    ('/blog/([0-9]+)/newcomment', PostComment),
    ('/blog/([0-9]+)/editcomment/([0-9]+)', EditComment),
    ('/blog/([0-9]+)/deletecomment/([0-9]+)', DeleteComment)
], debug=True)
