#!/usr/bin/env python3
"""Minimal vulnerable test server for scanner validation.
Endpoints:
  /echo?input=            Reflects input (XSS simulation)
  /file?name=             LFI simulation: if 'passwd' in name returns fake /etc/passwd snippet
  /redir?url=             Open redirect simulation
  /secret?key=            Secret leak if key matches 'debug'
Run:
  python tools/vuln_test_server.py --port 5000
"""
from flask import Flask, request, redirect
import argparse

app = Flask(__name__)

FAKE_PASSWD = "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"


@app.route('/echo')
def echo():
    val = request.args.get('input', '')
    # naive reflection (deliberately unsafe)
    return f"<html><body>Echo: {val}</body></html>", 200, {"Content-Type": "text/html"}


@app.route('/file')
def file():
    name = request.args.get('name', '')
    if 'passwd' in name:
        return FAKE_PASSWD, 200, {"Content-Type": "text/plain"}
    return f"Requested: {name}", 200, {"Content-Type": "text/plain"}


@app.route('/redir')
def redir():
    url = request.args.get('url', '')
    if url:
        return redirect(url, code=302)
    return 'No url provided', 400


@app.route('/secret')
def secret():
    key = request.args.get('key', '')
    if key == 'debug':
        return 'LEAK: INTERNAL_TOKEN=ABC123XYZ', 200
    return 'Denied', 403


@app.route('/')
def index():
    return 'Vuln Test Server Ready', 200


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=5000)
    args = parser.parse_args()
    app.run(host='0.0.0.0', port=args.port, debug=False)
