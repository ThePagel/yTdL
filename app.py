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
