import openai

# Initialize OpenAI API key
openai.api_key = 'your_openai_api_key'

def generate_playlist(genre, mood):
    prompt = f"Create a playlist of 10 songs for a {mood} mood in the {genre} genre."
    
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are a helpful assistant that creates music playlists."},
            {"role": "user", "content": prompt}
        ]
    )
    
    playlist = response.choices[0].message['content']
    return playlist
