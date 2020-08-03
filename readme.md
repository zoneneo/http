# 成熟的 python Web 开发框架
> 成熟的python Web 开发框架有 Django、Flask、Tornado等 
> Django 是一个高层次 Python Web 开发框架，特点是开发快速、代码较少、可扩展性强。
> Flask 是一个 Python Web 开发的微框架， 非常轻量、非常简单，基于它搭建 Web 系统都以分钟来计时，特别适合小微原型系统的开发。
> Tornado 是一个基于异步网络功能库的 Web 开发框架，它能支持几万个开放连接，适合高并发场景下的 Web 系统，服务高效稳定。
> web.py 俄罗斯排名第一的 Yandex 搜索引擎基于这个框架开发，Guido van Rossum 认为这是最好的 Python Web 框架。

> WSGI的全称是Python Web Server Gateway Interface，WSGI不是web服务器
最早的一个是CGI，后来出现了改进CGI性能的FasgCGI。FastCGI也被许多脚本语言所支持，PHP-FPM是一个PHP FastCGI管理器。
Java有专用的Servlet规范，WSGI的实现受Servlet的启发比较大。
> 在WSGI中有两种角色：一方称之为server或者gateway, 另一方称之为application或者framework。application可以提供一个可调用对象供server调用。
server负责接收HTTP请求，根据请求数据组装environ，定义start_response函数，然后调用application提供的可调用对象，将这两个参数提供给application。application根据environ信息执行业务逻辑，调用的结果会被封装成HTTP响应后发送给客户端。
## WSGI对application的要求有3个：
   - 实现一个可调用对象
   - 可调用对象接收两个参数，environ（一个dict，包含WSGI的环境信息）与start_response（一个响应请求的函数）
   - 返回一个iterable可迭代对象

> Django、Flask 遵循WSGI，后端使用werkzeug,除了选择现有的web框架,我们也可以选择werkzeug来实现简短的web框架。
> werkzeug实现基于http.server库的HTTPServer,基于BaseHTTPRequestHandler改写的WSGIRequestHandler。

# 通过一行命令
* python3 -m http.server 8000 --bind 127.0.0.1 

> 命令默认使用的SimpleHTTPRequestHandler启动web服务,相当如下程序。

```
import http.server
import socketserver

PORT = 8000

Handler = http.server.SimpleHTTPRequestHandler
with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print("serving at port", PORT)
    httpd.serve_forever()
```

>wsgiref是WSGI细则的一个参考实现，它提供了处理WSGI环境变量、response头和WSGI服务器基类。
这里重点使用python自带wsgiref库，实现带路由功能的application,这可以用于简单快速的开发测试。
wsgiref.simple_server实现了WSGIServer和WSGIRequestHandler,这些基于http.server和http.server.BaseHTTPRequestHandler
wsgiref.simple_server.make_server(host, port, app, server_class=WSGIServer, handler_class=WSGIRequestHandler)

```
from wsgiref.simple_server import make_server

def hello_world_app(environ, start_response):
    status = '200 OK'  # HTTP Status
    headers = [('Content-type', 'text/plain; charset=utf-8')]  # HTTP Headers
    start_response(status, headers)

    # The returned object is going to be printed
    return [b"Hello World"]

with make_server('', 8000, hello_world_app) as httpd:
    print("Serving on port 8000...")

    # Serve until process is killed
    httpd.serve_forever()
```




