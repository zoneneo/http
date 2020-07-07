#!/usr/bin/env python
#--coding:utf-8--
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from os import path
from urllib.parse import urlparse
import json

#Map的作用则是保存所有Rule对象。werkzeug库中的Map与Rule在Flask中的应用
class Flask(object):
    def __init__(self):
        self.url_map = {}
        
    def __call__(self, environ, start_response):  # 根据WSGI协议，middleware必须是可调用对象
        self.dispatch_request()
        return application(environ, start_response)
    
    def route(self, rule):  # Flask使用装饰器来完成url与处理函数的映射关系建立
        def decorator(f):   # 简单，侵入小，优雅
            self.url_map[rule] = f
            return f
        return decorator
    
    def dispath_request(self):
        url = get_url_from_environ() #解析environ获得url 
        return self.url_map[url]() #从url_map中找到对应的处理函数，并调用


app = Flask()


@app.route('/api/user',method='GET')
def get_user()：
	user={'name':'admin','email':'test@exmple.com'}
	return json.dumps(user)

@app.route('/api/user',method='POST')
def add_user()：
	msg={'status':'200','message':'ok','data':params}
	return json.dumps(msg)


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
    if not self.path.startswith('/api/'):
    	self._send_file(file)
    else:
        uri = urlparse(self.path)
        path, query = uri.path, uri.query
        func=app.get(path,method)
        res=func()
        content=res.encdoe('utf-8')
        self.send_response(200)
        self.send_header('Content-type','application/json')
        self.wfile.write(res)


    def do_GET(self):
        self._handle('GET')

    def do_POST(self):
        self._handle('POST')

    def do_PUT(self):
        self._handle('PUT')

    def do_DELETE(self):
        self._handle('DEL')



if __name__ == '__main__':
    host = ''
    port = 8000
    print('starting server, port', port)

    # Server settings
    server_address = ('', port)
    httpd = HTTPServer(server_address, MyHTTPRequestHandler)
    print('running server...')
    httpd.serve_forever()