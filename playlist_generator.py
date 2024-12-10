from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required
import openai

playlist_bp = Blueprint('playlist', __name__)

@playlist_bp.route('/playlist_generator', methods=['GET', 'POST'])
@login_required
def playlist_generator():
    if request.method == 'POST':
        prompt = request.form.get('prompt')
        openai.api_key = 'your_openai_api_key'
        response = openai.Completion.create(
            engine="text-davinci-003",
            prompt=prompt,
            max_tokens=150
        )
        playlist = response.choices[0].text.strip()
        return render_template('playlist_generator.html', playlist=playlist)
    return render_template('playlist_generator.html')
