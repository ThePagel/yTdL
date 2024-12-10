from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import CSRFProtect, FlaskForm

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    admin = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class SimpleForm(FlaskForm):
    pass

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
            app.logger.info(f'Failed login attempt for user: {username}')
    return render_template('login.html', form=form)

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    form = SimpleForm()
    if User.query.filter_by(admin=True).first():
        return redirect(url_for('login'))
    if request.method == 'POST' and form.validate_on_submit():
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_admin = User(username=username, password=hashed_password, admin=True)
        db.session.add(new_admin)
        db.session.commit()
        flash('Admin account created successfully.')
        return redirect(url_for('login'))
    return render_template('setup.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
@login_required
def signup():
    form = SimpleForm()
    if current_user.admin:  # Only admin can create new users
        if request.method == 'POST' and form.validate_on_submit():
            username = request.form.get('username')
            password = request.form.get('password')
            admin = True if request.form.get('admin') == 'on' else False
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, password=hashed_password, admin=admin)
            db.session.add(new_user)
            db.session.commit()
            flash('User created successfully.')
            return redirect(url_for('dashboard'))
        return render_template('signup.html', form=form)
    else:
        flash('Only admins can create new users.')
        return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/user_management')
@login_required
def user_management():
    form = SimpleForm()
    if current_user.admin:
        users = User.query.all()
        return render_template('user_management.html', users=users, form=form)
    else:
        flash('Access denied. Admins only.')
        return redirect(url_for('dashboard'))

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    form = SimpleForm()
    if current_user.admin:
        user = User.query.get_or_404(user_id)
        if request.method == 'POST' and form.validate_on_submit():
            user.username = request.form['username']
            user.admin = True if request.form.get('admin') == 'on' else False
            db.session.commit()
            flash('User updated successfully.')
            return redirect(url_for('user_management'))
        return render_template('edit_user.html', user=user, form=form)
    else:
        flash('Access denied. Admins only.')
        return redirect(url_for('dashboard'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    form = SimpleForm()
    if current_user.admin:
        user = User.query.get_or_404(user_id)
        if user.id == current_user.id:
            flash('You cannot delete your own account.')
            return redirect(url_for('user_management'))
        else:
            db.session.delete(user)
            db.session.commit()
            flash('User deleted successfully.')
            return redirect(url_for('user_management'))
    else:
        flash('Access denied. Admins only.')
        return redirect(url_for('dashboard'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = SimpleForm()
    if request.method == 'POST' and form.validate_on_submit():
        current_user.username = request.form['username']
        db.session.commit()
        flash('Profile updated successfully.')
    return render_template('profile.html', form=form)

@app.route('/reset_password', methods=['GET', 'POST'])
@login_required
def reset_password():
    form = SimpleForm()
    if request.method == 'POST' and form.validate_on_submit():
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        if bcrypt.check_password_hash(current_user.password, current_password):
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            current_user.password = hashed_password
            db.session.commit()
            flash('Password reset successfully.')
        else:
            flash('Current password is incorrect.')
            app.logger.warning(f'Failed password reset attempt for user: {current_user.username}')
    return render_template('reset_password.html', form=form)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0')
