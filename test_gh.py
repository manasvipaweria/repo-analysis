import urllib.request
import json
req = urllib.request.Request("https://api.github.com/repos/manasvipaweria/repo-analysis", headers={"User-Agent": "Python"})
try:
    with urllib.request.urlopen(req) as response:
        data = json.loads(response.read().decode())
        print(data.get("name"))
except Exception as e:
    print(e)
