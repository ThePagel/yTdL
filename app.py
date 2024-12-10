from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import CSRFProtect, FlaskForm
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
csrf = CSRFProtect(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

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
    if form.validate_on_submit():
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
    if form.validate_on_submit():
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
        if form.validate_on_submit():
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
    form = SimpleForm()
    return render_template('dashboard.html', form=form)

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
        if form.validate_on_submit():
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
    if form.validate_on_submit():
        current_user.username = request.form['username']
        db.session.commit()
        flash('Profile updated successfully.')
    return render_template('profile.html', form=form)

@app.route('/reset_password', methods=['GET', 'POST'])
@login_required
def reset_password():
    form = SimpleForm()
    if form.validate_on_submit():
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

@app.route('/create_playlist', methods=['POST'])
@login_required
def create_playlist():
    form = SimpleForm()
    if form.validate_on_submit():
        song = request.form.get('song')
        artist = request.form.get('artist')
        # Call the function to get similar songs
        similar_songs = get_similar_songs(song, artist)
        if not similar_songs:
            flash('No similar songs found or there was an error with the API. Please try a different song.')
        return render_template('playlist.html', songs=similar_songs)
    flash('CSRF token is missing or incorrect.')
    return redirect(url_for('dashboard'))

def get_similar_songs(song, artist):
    LASTFM_API_KEY = '1983ea74946115c4fa607ff051dede83'
    url = f'http://ws.audioscrobbler.com/2.0/?method=track.getsimilar&track={song}&artist={artist}&api_key={LASTFM_API_KEY}&format=json'
    response = requests.get(url)
    
    app.logger.info(f'Request URL: {url}')  # Log the request URL for debugging
    if response.status_code == 200:
        data = response.json()
        app.logger.info(f'API Response: {data}')  # Log the API response for debugging
        if 'similartracks' in data:
            similar_songs = data['similartracks']['track']
            return [track['name'] for track in similar_songs]
        else:
            app.logger.error(f'KeyError: "similartracks" not found in response for song: {song} by {artist}')
            app.logger.error(f'Full Response: {data}')
            # Fallback: Test with a known song
            fallback_url = f'http://ws.audioscrobbler.com/2.0/?method=track.getsimilar&track=Bohemian+Rhapsody&artist=Queen&api_key={LASTFM_API_KEY}&format=json'
            fallback_response = requests.get(fallback_url)
            fallback_data = fallback_response.json()
            if 'similartracks' in fallback_data:
                fallback_songs = fallback_data['similartracks']['track']
                app.logger.info(f'Fallback Response: {fallback_data}')
                return [track['name'] for track in fallback_songs]
            else:
                return []
    else:
        app.logger.error(f'Error fetching similar songs: {response.status_code}')
        app.logger.error(f'Full Response: {response.text}')
        return []

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0')
