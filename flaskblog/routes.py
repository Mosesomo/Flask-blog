#!/usr/bin/python3
import os
from flask import render_template, url_for, flash, redirect, request, abort, send_from_directory, jsonify
from flaskblog import app, db, bcrypt, mail, photos, serial, oauth, videos
from flaskblog.models import User, Post, Like, Comment
from flaskblog.form import Registration, LoginForm, PostContent, UpdateAccount, RequestResetForm, ResetPasswordForm
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message
from authlib.integrations.flask_client import OAuth
from bs4 import BeautifulSoup


@app.route('/')
@app.route('/home')
def home():
    page = request.args.get('page', 1, type=int)
    per_page = 2
    posts = Post.query.order_by(Post.date_posted.desc()).\
        paginate(page=page, per_page=per_page)
    truncated_posts = []
    for post in posts.items:
        truncated_content = truncate_html(post.content, max_length=100)
        truncated_posts.append({
            'post': post,
            'truncated_content': truncated_content
        })
    return render_template('home.html', posts=posts, truncated_posts=truncated_posts)


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
        # print("Token:", token)
        
        # Manually inspect the token
        user_info = oauth.google.parse_id_token(token, None)
        # print("User Info:", user_info)
        
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

@app.route('/uploads/videos/<filename>')
def upload_video(filename):
    return send_from_directory(app.config['UPLOADED_VIDEOS_DEST'], filename)


def truncate_html(html, max_length):
    """
    Truncate the HTML content to a certain number of characters,
    preserving the HTML structure and excluding images.
    """
    soup = BeautifulSoup(html, 'html.parser')
    text = ''
    truncated = False

    for element in soup.recursiveChildGenerator():
        if isinstance(element, str):
            if len(text) + len(element) > max_length:
                text += element[:max_length - len(text)]
                truncated = True
                break
            text += element
        elif element.name in ['p', 'br', 'div']:
            text += ' '
        elif element.name == 'img':
            # Include the image tag in the truncated content
            text += str(element)
            continue  # Skip further processing for this image
        if len(text) >= max_length:
            truncated = True
            break

    # Return the truncated content with an ellipsis if truncated
    if truncated:
        return text.strip() + '...'
    return str(soup)  # Return the original content if not truncated

@app.route('/post/new', methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostContent()
    if form.validate_on_submit():
        filename_url = None
        if form.media.data:
            filename = form.media.data.filename
            if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                filename = photos.save(form.media.data)
                filename_url = url_for('upload_photo', filename=filename)
            elif filename.lower().endswith(('.mp4', '.webm', '.ogg')):
                filename = videos.save(form.media.data)
                filename_url = url_for('upload_video', filename=filename)
        
        post = Post(
            title=form.title.data,
            content=form.content.data,
            media=filename_url,
            author=current_user
        )
        db.session.add(post)
        db.session.commit()
        flash("Post created successfully", 'success')
        return redirect(url_for('home'))
    
    return render_template('post.html', title='New Post', form=form, legend='New post')


@app.route('/post/<int:post_id>')
def post(post_id):
    post = Post.query.get_or_404(post_id)
    truncated_content = truncate_html(post.content, max_length=300)
    return render_template('create_post.html', title=post.title,
                           post=post, truncated_content=truncated_content)


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


@app.route('/upload', methods=['POST'])
def upload():
    if 'upload' in request.files:
        file = request.files['upload']
        
        # Save image
        if file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
            filename = photos.save(file)
            url = url_for('uploaded_photo', filename=filename, _external=True)
        elif file.filename.lower().endswith(('.mp4', '.webm', '.ogg')):
            filename = videos.save(file)
            url = url_for('uploaded_video', filename=filename, _external=True)
        
        # Unsupported file type
        else:
            return jsonify({"error": "Invalid file format"}), 400

        return jsonify({
            "uploaded": 1,
            "fileName": filename,
            "url": url
        })
    return jsonify({"error": "No file uploaded"}), 400


@app.route('/upload_image', methods=['POST'])
def upload_image():
    if 'upload' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['upload']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Return a JSON response with the URL of the uploaded file
        url = url_for('uploaded_file', filename=filename, _external=True)
        return jsonify({'url': url}), 200

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


@app.route('/post/<int:post_id>/like', methods=['POST'])
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    like = Like.query.filter_by(user_id=current_user.id, post_id=post.id).first()
    
    if like:
        db.session.delete(like)
        db.session.commit()
        flash('You unliked this post', 'success')
    else:
        new_like = Like(user_id=current_user.id, post_id=post.id)
        db.session.add(new_like)
        db.session.commit()
        flash('You liked this post', 'success')
    
    return redirect(url_for('post', post_id=post_id))
