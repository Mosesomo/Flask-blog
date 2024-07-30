#!/usr/bin/python3
import os
from flask import render_template, url_for, flash, redirect, request, abort, send_from_directory
from flaskblog import app, db, bcrypt, mail, photos, serial, oauth
from flaskblog.models import User, Post
from flaskblog.form import Registration, LoginForm, PostContent, UpdateAccount, RequestResetForm, ResetPasswordForm
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message
from authlib.integrations.flask_client import OAuth


@app.route('/')
@app.route('/home')
def home():
    page = request.args.get('page', 1, type=int)
    per_page = 2
    posts = Post.query.order_by(Post.date_posted.desc()).\
        paginate(page=page, per_page=per_page)
    return render_template('home.html', posts=posts)


@app.route('/about')
def about():
    return render_template('about.html', title='About')


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = Registration()
    if form.validate_on_submit():
        hashed_password = (bcrypt.generate_password_hash
                           (form.password.data)
                           .decode('utf-8'))
        user = User(username=form.username.data,
                    email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('register.html', title='Register', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password,
                                               form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password',
                  'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/google/')
def google():
    # Google OAuth configuration
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
    
    CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url=CONF_URL,
        client_kwargs={
            'scope': 'openid email profile',
            'nonce': 'some_nonce_value'
        }
    )
    
    redirect_uri = url_for('google_auth', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/google/auth/')
def google_auth():
    try:
        token = oauth.google.authorize_access_token()
        print("Token:", token)
        
        # Manually inspect the token
        user_info = oauth.google.parse_id_token(token, None)
        print("User Info:", user_info)
        
        google_id = user_info.get('sub')
        email = user_info.get('email')
        username = user_info.get('name', email.split('@')[0])
        picture = user_info.get('picture', 'default.jpg')
        password = user_info.get('at_hash')

        user = User.query.filter_by(google_id=google_id).first()
        if user is None:
            user = User.query.filter_by(email=email).first()
            if user:
                flash('Email address already in use. Please log in using your credentials.', 'danger')
                return redirect(url_for('login'))
            
            user = User(google_id=google_id, username=username, email=email, password=password, image=picture)
            db.session.add(user)
            db.session.commit()
        
        login_user(user)
        flash('You have been logged in!', 'success')
        return redirect(url_for('home'))
    
    except Exception as e:
        print(f"Error during authentication: {e}")
        flash('Authentication failed. Please try again.', 'danger')
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccount()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = photos.save(form.picture.data)
            filename_url = url_for('upload_photo', filename=picture_file)
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.image = filename_url
        db.session.commit()
        flash('Account updated successfully!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('account.html', title='Account',
                           form=form)

@app.route('/uploads/photos/<filename>')
def upload_photo(filename):
    return send_from_directory(app.config['UPLOADED_PHOTOS_DEST'], filename)

@app.route('/post/new', methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostContent()
    if form.validate_on_submit():
        post = Post(title=form.title.data,
                    content=form.content.data,
                    author=current_user)
        db.session.add(post)
        db.session.commit()
        flash("Post created successfully", 'success')
        return redirect(url_for('home'))
    return render_template('post.html', title='New Post',
                           form=form, legend='New post')


@app.route('/post/<int:post_id>')
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('create_post.html', title=post.title, post=post)


@app.route('/post/<int:post_id>/update', methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = PostContent()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('Your post has been updated', 'success')
        return redirect(url_for('post', post_id=post.id))
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
    return render_template('post.html', title='Update Post',
                           form=form, legend='Update Post')


@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('home'))


@app.route('/user/<string:username>')
def user_post(username):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username)\
        .first_or_404()
    per_page = 2
    posts = Post.query.filter_by(author=user)\
        .order_by(Post.date_posted.desc())\
        .paginate(page=page, per_page=per_page)
    return render_template('user_post.html', posts=posts, user=user)


def generate_reset_token(email):
    return serial.dumps(email, salt='password-reset')

def send_reset_email(email, reset_link):
    msg = Message('Reset Password Link', sender='noreply@mosesomo.tech', recipients=[email])
    msg.body = f'Please click the following link to reset your password: {reset_link}'
    mail.send(msg)
    token = serial.dumps(email, salt='password-reset')
    return token

@app.route("/reset_password", methods=['GET', 'POST'])
def request_reset():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = generate_reset_token(user.email)
            reset_link = url_for('request_token', token=token, _external=True)
            send_reset_email(user.email, reset_link)
            flash('An email has been sent with instructions to reset your password', 'info')
        else:
            flash('Email not found', 'warning')
    return render_template('reset_request.html', title='Reset Password', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def request_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.very_reset_token(token)
    if user is None:
        flash('That is an invalid token', 'warning')
        return redirect(url_for('request_reset'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', title='Reset Password', form=form)