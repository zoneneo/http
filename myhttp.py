import os
from os import path
import socketserver
from http.server import BaseHTTPRequestHandler,SimpleHTTPRequestHandler,HTTPServer
from urllib.parse import urlparse


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


    def do_GET(self):
        file = self._get_realpath()
        self._send_file(file)

    def do_POST(self,method):
        uri = urlparse(self.path)
        path, query = uri.path, uri.query
        # func=app.get(path,method)
        # res=func()
        # content=res.encdoe('utf-8')
        content='%s,%s'%(path,query)
        self.send_response(200)
        self.send_header('Content-type','application/json')
        self.wfile.write(content)



if __name__ == '__main__':

    PORT = 8000
    #Handler = MyHTTPRequestHandler
    Handler = SimpleHTTPRequestHandler
    with socketserver.TCPServer(('',PORT), Handler) as httpd:
        print("serving at port", PORT)
        httpd.serve_forever()
