import urllib.request, urllib.parse, re

headers = {'User-Agent': 'Mozilla/5.0'}
queries = [
    '"three of them, to be exact" ctf',
    '"three of them to be exact"',
    '"really like pies" ctf',
    '"Pie. Pie. Pie."',
    '73665d1406069b625aa34884e219d0c2ec5bf3957acb92ffde'
]

for q in queries:
    url = 'https://html.duckduckgo.com/html/?q=' + urllib.parse.quote(q)
    try:
        req = urllib.request.Request(url, headers=headers)
        html = urllib.request.urlopen(req, timeout=6).read().decode('utf-8', errors='ignore')
        snippets = re.findall(r'<a class="result__snippet[^>]*>(.*?)</a>', html)
        if snippets:
            print(f"=== {q} ===")
            for s in snippets[:2]:
                clean = re.sub(r'<[^>]+>', '', s).strip()
                print(" -", clean)
    except Exception as e:
        print(f"Error on {q}: {e}")
