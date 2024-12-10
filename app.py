from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm, CSRFProtect  # Import CSRFProtect
import requests

# Initialize the app and its components
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
csrf = CSRFProtect(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Define the User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    admin = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Define forms
class SimpleForm(FlaskForm):
    pass

# Utility function for formatting inputs
def format_input(text):
    return text.replace(' ', '').title()

# Fetch top tracks for a given artist
def fetch_top_tracks(artist):
    LASTFM_API_KEY = '1983ea74946115c4fa607ff051dede83'
    url = f'http://ws.audioscrobbler.com/2.0/?method=artist.gettoptracks&artist={format_input(artist)}&api_key={LASTFM_API_KEY}&format=json'
    response = requests.get(url)
    if response.status_code == 200 and 'toptracks' in response.json():
        return [track['name'] for track in response.json()['toptracks']['track']]
    return []

# Fetch similar songs or artists
def get_similar_songs(song=None, artist=None):
    LASTFM_API_KEY = '1983ea74946115c4fa607ff051dede83'
    url = f"http://ws.audioscrobbler.com/2.0/?method={'track.getsimilar' if song else 'artist.getsimilar'}&{'track='+format_input(song)+'&' if song else ''}artist={format_input(artist)}&api_key={LASTFM_API_KEY}&format=json"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        key = 'similartracks' if song else 'similarartists'
        return [item['name'] for item in data.get(key, {}).get('track' if song else 'artist', [])]
    return []

# Route for home page
@app.route('/')
def index():
    return redirect(url_for('login') if User.query.filter_by(admin=True).first() else url_for('setup'))

# Route for login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = SimpleForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=request.form['username']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Login failed. Check your username and password.')
    return render_template('login.html', form=form)

# Route for setup page
@app.route('/setup', methods=['GET', 'POST'])
def setup():
    form = SimpleForm()
    if User.query.filter_by(admin=True).first():
        return redirect(url_for('login'))
    if form.validate_on_submit():
        new_admin = User(username=request.form['username'], password=bcrypt.generate_password_hash(request.form['password']).decode('utf-8'), admin=True)
        db.session.add(new_admin)
        db.session.commit()
        flash('Admin account created successfully.')
        return redirect(url_for('login'))
    return render_template('setup.html', form=form)

# Route for signing up a new user
@app.route('/signup', methods=['GET', 'POST'])
@login_required
def signup():
    if not current_user.admin:
        flash('Only admins can create new users.')
        return redirect(url_for('dashboard'))
    form = SimpleForm()
    if form.validate_on_submit():
        new_user = User(username=request.form['username'], password=bcrypt.generate_password_hash(request.form['password']).decode('utf-8'), admin='on' in request.form)
        db.session.add(new_user)
        db.session.commit()
        flash('User created successfully.')
        return redirect(url_for('dashboard'))
    return render_template('signup.html', form=form)

# Route for logging out
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Route for dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', form=SimpleForm())

# Route for user management
@app.route('/user_management')
@login_required
def user_management():
    return render_template('user_management.html', users=User.query.all(), form=SimpleForm()) if current_user.admin else (flash('Access denied. Admins only.'), redirect(url_for('dashboard')))

# Route for editing a user
@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.admin:
        flash('Access denied. Admins only.')
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    form = SimpleForm()
    if form.validate_on_submit():
        user.username = request.form['username']
        user.admin = 'on' in request.form
        db.session.commit()
        flash('User updated successfully.')
        return redirect(url_for('user_management'))
    return render_template('edit_user.html', user=user, form=form)

# Route for deleting a user
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.admin:
        flash('Access denied. Admins only.')
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot delete your own account.')
    else:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.')
    return redirect(url_for('user_management'))

# Route for profile page
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = SimpleForm()
    if form.validate_on_submit():
        current_user.username = request.form['username']
        db.session.commit()
        flash('Profile updated successfully.')
    return render_template('profile.html', form=form)

# Route for resetting password
@app.route('/reset_password', methods=['GET', 'POST'])
@login_required
def reset_password():
    form = SimpleForm()
    if form.validate_on_submit():
        if bcrypt.check_password_hash(current_user.password, request.form['current_password']):
            current_user.password = bcrypt.generate_password_hash(request.form['new_password']).decode('utf-8')
            db.session.commit()
            flash('Password reset successfully.')
        else:
            flash('Current password is incorrect.')
    return render_template('reset_password.html', form=form)

# Route for creating a playlist
@app.route('/create_playlist', methods=['POST'])
@login_required
def create_playlist():
    form = SimpleForm()
    if form.validate_on_submit():
        similar_songs = get_similar_songs(request.form.get('song'), request.form.get('artist'))
        if not similar_songs:
            flash('No similar songs found or there was an error with the API. Please try a different song or artist.')
        return render_template('playlist.html', songs=similar_songs)
    flash('CSRF token is missing or incorrect.')
    return redirect(url_for('dashboard'))

# Route to get songs for an artist
@app.route('/get_songs', methods=['GET'])
def get_songs():
    return {'songs': fetch_top_tracks(request.args.get('artist'))}

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0')
