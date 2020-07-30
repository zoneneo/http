
#/usr/bin/env python

# Note The SimpleHTTPServer module has been merged into http.server in Python 3. 
#socketserver servers don't support use as context managers before Python 3.6

import SimpleHTTPServer
import SocketServer

PORT = 8000
Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
httpd = SocketServer.TCPServer(("", PORT), Handler)
print "serving at port", PORT
httpd.serve_forever()