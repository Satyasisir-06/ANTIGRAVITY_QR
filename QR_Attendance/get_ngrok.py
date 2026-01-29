import urllib.request
import json

try:
    with urllib.request.urlopen("http://localhost:4040/api/tunnels") as response:
        data = json.loads(response.read().decode())
        public_url = data['tunnels'][0]['public_url']
        with open("url.txt", "w") as f:
            f.write(public_url)
        print(f"URL found: {public_url}")
except Exception as e:
    print(f"Error: {e}")
