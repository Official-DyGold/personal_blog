import os
import secrets
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort
from flaskblog import app, db, bcrypt, mail
from flaskblog.forms import (
    registrationForm, 
    loginForm, 
    updateProfileForm, 
    postForm, 
    requestResetForm, 
    resetPassword
    )
from flaskblog.models import User, Post
from flask_login import login_user, current_user , logout_user, login_required
from flask_mail import Message

@app.route("/")
@app.route("/home")
def home():
    page=request.args.get('page', 1, type=int)
    posts=Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    return render_template("home.html", posts=posts)

@app.route("/about")
def about():
    return render_template("about.html", title= 'About')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = registrationForm()
    if form.validate_on_submit():
        hashedPassword = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashedPassword
            )
        db.session.add(user)
        db.session.commit()
        flash('Your account as been created! now you can login', 'success')
        return redirect(url_for('login'))
    return render_template("register.html", title= 'Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = loginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember = form.remember.data)
            nextPage = request.args.get('next')
            return redirect(nextPage) if nextPage else redirect(url_for('home'))
        else:
            flash('Email or Password incorrect', 'danger')
    return render_template("login.html", title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

def savePicture(formPicture):
    randomHex = secrets.token_hex(8)
    _, fExt = os.path.splitext(formPicture.filename)
    pictureFilename = randomHex + fExt
    picturePath = os.path.join(app.root_path, 'static/profile_pics', pictureFilename)

    outPutSize = (250, 250)
    imageAfter = Image.open(formPicture)
    imageAfter.thumbnail(outPutSize)
    imageAfter.save(picturePath)

    return pictureFilename   

@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    form = updateProfileForm()
    if form.validate_on_submit():
        if form.profilePicture.data:
            pictureFilename = savePicture(form.profilePicture.data)
            current_user.imageFile = pictureFilename
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    imageFile = url_for('static', filename='profile_pics/' + current_user.imageFile)
    return render_template("profile.html", title='Profile', imageFile=imageFile, form=form)

@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def postNew():
    form = postForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your post as been created!', 'success')
        return redirect(url_for('home'))
    return render_template("create_post.html", title='New Post', form=form, legend='New Post')

@app.route("/post/<int:postID>")
@login_required
def postEdit(postID):
    post=Post.query.get_or_404(postID)
    return render_template("post_edit.html", title='Edit Post', post=post)

@app.route("/post/<int:postID>/update", methods=['GET', 'POST'])
@login_required
def updatePost(postID):
    post=Post.query.get_or_404(postID)
    if post.author != current_user:
        abort(403)
    form=postForm()
    if form.validate_on_submit():
        post.title = form.title.data 
        post.content = form.content.data
        db.session.commit()
        flash('You post has been updated!', 'success')
        return redirect(url_for('postEdit', postID=post.id))
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
    return render_template("create_post.html", title='New Post', form=form, legend='Update Post')

@app.route("/post/<int:postID>/delete_post", methods=['POST'])
@login_required
def deletePost(postID):
    post=Post.query.get_or_404(postID)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Your post as been deleted!', 'success')
    return redirect(url_for('home'))

@app.route("/user/<string:username>")
def userPost(username):
    page=request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    posts=Post.query.filter_by(author=user).order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    return render_template("user_posts.html", title=f'Post by {username}', posts=posts, user=user)

def sendResetEmail(user):
    token = user.getResetToken()
    msg = Message('Password Reset Request', sender='noreply@demo.com', recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link: 
    {url_for('resetPasswordRequest', token=token, _external = True)}

    if you did not make this request simply ignore this message and no changes will be made.
    '''

@app.route("/reset_password", methods=['GET', 'POST'])
def resetPasswordRequest():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = requestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        try: 
            if sendResetEmail(user) == None:
                flash('No message to send', 'danger')
            else:
                sendResetEmail(user)
                print(sendResetEmail(user))
                flash('An email as been sent with instruction to reset your password.', 'info')
        except Exception as e:
            print(f"Error sending email: {e}")
        return redirect(url_for('login'))
    return render_template("reset_password.html", title='Reset Password', form=form)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def resetPasswordConfirm(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verifyResetToken(url_for('home'))
    if user is None:
        flash('That is an invalid or expired Token', 'warming')
        return redirect(url_for('resetPasswordRequest'))
    form = resetPassword()
    if form.validate_on_submit():
        hashedPassword = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashedPassword
        db.session.commit()
        flash('Your password has been updated! You are now able to login', 'success')
        return redirect(url_for('login'))
    return render_template("reset_password_confirm.html", title='Reset Password Confirm', form=form)