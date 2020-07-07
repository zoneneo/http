import http.server
import socketserver

import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from os import path
from urllib.parse import urlparse
import json

class MyHTTPRequestHandler(BaseHTTPRequestHandler):
    curdir = path.dirname(path.realpath(__file__))
    content_type={'.htm':'text/html','.html':'text/html','.htc':'text/html',
    '.jpg':'image/jpeg','.jpeg':'image/jpeg','.png':'application/x-png','.gif':'image/gif',
    '.xml':'text/xml','.ico':'image/x-icon','.json':'application/json'}

    def _get_realpath(self):
        uri = urlparse(self.path)
        filepath, query = uri.path, uri.query
        if filepath.endswith('/'):
            filepath += 'index.html'
        return path.realpath(self.curdir + os.sep + filepath)
        

    def _send_file(self, file):
        name, ext = path.splitext(file)
        c_type=self.content_type.get(ext)
        if c_type is None:
            self.send_error(403,'File Not Found: %s' % self.path)
        try:
            with open(file,'rb') as f:
                content = f.read()
                self.send_response(200)
                self.send_header('Content-type',c_type)
                self.end_headers()
                self.wfile.write(content)
        except IOError:
            self.send_error(404,'File Not Found: %s' % self.path)

    def _handle(self,method):
        file = self._get_realpath()
        self._send_file(file)


HOST = ""
PORT = 80

Handler = http.server.SimpleHTTPRequestHandler

with socketserver.TCPServer((HOST, PORT), Handler) as httpd:
    print("serving at port", PORT)
    httpd.serve_forever()