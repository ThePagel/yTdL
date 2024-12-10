from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, login_required, logout_user, current_user
from your_application import app, db, bcrypt
from your_application.models import User
from your_application.forms import SimpleForm

# Existing routes here
@app.route('/')
def index():
    admin_exists = User.query.filter_by(admin=True).first()
    if admin_exists:
        return redirect(url_for('login'))
    else:
        return redirect(url_for('setup'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = SimpleForm()
    if request.method == 'POST' and form.validate_on_submit():
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your username and password.')
    return render_template('login.html', form=form)

# ... other existing routes ...
