from flask import Flask, render_template,request, redirect, url_for, flash
from smtplib import SMTP
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, EmailField, PasswordField
from wtforms.validators import DataRequired, url
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from flask_ckeditor import CKEditorField
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from functools import wraps
from flask import abort




app = Flask(__name__)
ckeditor = CKEditor(app)
bootstrap = Bootstrap(app)

my_email = "anonymous2001at@gmail.com"
app_password = "joaf urcu rwmc dtks"

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))



def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)        
    return decorated_function


db = SQLAlchemy()
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///blogs.db"
db.init_app(app)

app.config['SECRET_KEY'] = 'any secret string'

today = datetime.now()
current_date = today.strftime("%d %B,%Y")


class Comments(db.Model):
    __tablename__="Comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    
    author_id = db.Column(db.Integer, db.ForeignKey("Users.id"))
    comment_author = relationship("User", back_populates="comments")
    



# Database for registering users
class User(db.Model, UserMixin):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    
    posts = relationship("Blogs", back_populates="author")
    comments = relationship("Comments", back_populates="comment_author")
    

#Database for Blogs
class Blogs(db.Model, UserMixin):
    __tablename__="Blogs"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('Users.id'))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String, unique=True)
    subtitle = db.Column(db.String)
    date = db.Column(db.String)
    image = db.Column(db.String)
    body = db.Column(db.String)



#FORMS
class CreatePostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    subtitle = StringField('Subtitle', validators=[DataRequired()])
    author = StringField('Author')
    body = CKEditorField('Body', validators=[DataRequired()])
    img_url = StringField('Img url', validators=[DataRequired(), url()])
    submit = SubmitField('Submit')
    

class RegisterForm(FlaskForm):
    Name = StringField(' Your Name', validators=[DataRequired()])
    Email = EmailField('Email Address', validators=[DataRequired()])
    Password = StringField('Password', validators=[DataRequired()])
    Submit = SubmitField('Register')


class LoginForm(FlaskForm):
    Email = EmailField('Email Address', validators=[DataRequired()])
    Password = StringField('Password', validators=[DataRequired()])
    Submit = SubmitField('Login')
    
class CommentForm(FlaskForm):
    comment_text = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")
    




@app.route("/")
def index():
    all_posts = Blogs.query.all()
    return render_template("index.html", title="Welcome to Blogs", blogs=all_posts, current_user=current_user)

@app.route("/about")
def about():
    return render_template("about.html", title="About me",current_user=current_user)

@app.route("/contact")
def contact():
    return render_template("contact.html", title="Contact me",current_user=current_user)

@app.route("/form-entry", methods=["GET","POST"])
def formentry():
    name = request.form['name']
    email = request.form['email']
    phone = request.form['phonenumber']
    message = request.form['message']
    with SMTP('smtp.gmail.com') as connection:
        connection.starttls()
        connection.login(user=my_email, password=app_password)
        connection.sendmail(
            from_addr=my_email,
            to_addrs=email,
            msg=f"You got an email from {name} having phone number {phone} message:{message}"
        )
    return "Form submitted successfully"

    

@app.route("/post/<n>", methods=["GET","POST"])
def post(n):
    n=int(n)
    form = CommentForm()
    requested_post = Blogs.query.get(n)
    with app.app_context():
        blog=Blogs.query.filter_by(id=n).first()
        id = blog.id
        title = blog.title
        subtitle = blog.subtitle
        author = blog.author.name
        body = blog.body
        date = blog.date
        img_url = blog.image
        
        if form.validate_on_submit():
            if not current_user.is_authenticated:
                flash("You need to login or register to comment.")
                return redirect(url_for("login"))

            new_comment = Comments(
                text=form.comment_text.data,
                comment_author=current_user,
                parent_post=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
            
        return render_template("post.html", title=title, subtitle=subtitle,author=author,date=date, content=body, img_url=img_url, blog_id=id, current_user=current_user,form=form, post=requested_post)


@app.route("/add", methods=["GET","POST"])
@login_required
@admin_only
def add():
    form = CreatePostForm()
    
    
    if request.method == "POST":
       title = form.title.data
       subtitle = form.subtitle.data
       body = form.body.data
       img_url = form.img_url.data
       date=current_date
       author=current_user
       new_blog = Blogs(title=title,subtitle=subtitle,body=body,image=img_url,date=date,author=author)
       db.session.add(new_blog)
       db.session.commit()
       return redirect('/')
    return render_template('add.html', form=form, current_user=current_user)

@app.route("/edit/<n>", methods=["GET", "POST"])
@login_required
@admin_only
def edit(n):
    n=int(n)
    current_blog = Blogs.query.get(n)
    edit_form = CreatePostForm(
    title = current_blog.title,
    subtitle = current_blog.subtitle,
    author = current_blog.author,
    img_url = current_blog.image,
    body = current_blog.body
    )
    
    if request.method == "POST" and edit_form.validate_on_submit:
        with app.app_context():
            current_blog.title = edit_form.title
            current_blog.subtitle = edit_form.subtitle
            current_blog.author = edit_form.author
            current_blog.img_url = edit_form.img_url
            current_blog.body = edit_form.body
            db.session.commit()
            return redirect('/')
    return render_template('edit.html',form=edit_form,n=n, current_user=current_user)


@app.route('/delete/<int:n>')
@admin_only
def delete(n):
    with app.app_context():
        blog = Blogs.query.get(n)
        db.session.delete(blog)
        db.session.commit()
        return redirect("/")
    

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.Name.data
        email = form.Email.data.lower()
        user_db = User.query.filter_by(email=email).first()
        if user_db:
            flash("User already exists!!")
        else:
            hashed_password = generate_password_hash(
                password = form.Password.data,
                method='pbkdf2:sha256',
                salt_length=16
            )
            with app.app_context():
                new_user = User(
                    name=name,
                    email=email,
                    password=hashed_password
                )
                db.session.add(new_user)
                db.session.commit()
            return redirect('/login')
    return render_template('register.html', form=form, current_user=current_user)

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email=form.Email.data.lower()
        password=form.Password.data
        with app.app_context():
            user_db = User.query.filter_by(email=email).first()
            login_user(user_db)
            
            if not user_db:
                flash("User doesn't exists try again!!")
                return redirect("/login")
            
            if email == user_db.email and not check_password_hash(user_db.password, password):
                flash("Password Incorrect!!")
                return redirect("/login")
            
            if email == user_db.email and check_password_hash(user_db.password, password):
                return redirect("/")
            db.session.commit()
            
            
    return render_template("login.html", form=form, current_user=current_user)

@app.route("/logout")
def logout():
    logout_user()
    return redirect("/")


# with app.app_context():
#     db.create_all()

if __name__ == "__main__":
    app.run(debug=True)