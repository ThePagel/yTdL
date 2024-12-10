from flask import Blueprint, render_template, request
from flask_login import login_required
import openai
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField

# Define the form
class PlaylistForm(FlaskForm):
    prompt = StringField('Enter your preferences:')
    submit = SubmitField('Generate Playlist')

playlist_bp = Blueprint('playlist', __name__)

@playlist_bp.route('/generator', methods=['GET', 'POST'])
@login_required
def playlist_generator():
    form = PlaylistForm()
    playlist = None
    if request.method == 'POST' and form.validate_on_submit():
        prompt = form.prompt.data
        openai.api_key = 'your_openai_api_key'
        response = openai.Completion.create(
            engine="text-davinci-003",
            prompt=prompt,
            max_tokens=150
        )
        playlist = response.choices[0].text.strip()
    return render_template('playlist_generator.html', form=form, playlist=playlist)
