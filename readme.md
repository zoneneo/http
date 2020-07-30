>成熟的web服务可选Django、Flask、Tornado等 Web 开发框架
> Django 是一个高层次 Python Web 开发框架，特点是开发快速、代码较少、可扩展性强。
> Flask 是一个 Python Web 开发的微框架， 非常轻量、非常简单，基于它搭建 Web 系统都以分钟来计时，特别适合小微原型系统的开发。
> Tornado 是一个基于异步网络功能库的 Web 开发框架，它能支持几万个开放连接，适合高并发场景下的 Web 系统，服务高效稳定。
> web.py 俄罗斯排名第一的 Yandex 搜索引擎基于这个框架开发，Guido van Rossum 认为这是最好的 Python Web 框架。

>WSGI的全称是Python Web Server Gateway Interface，WSGI不是web服务器
最早的一个是CGI，后来出现了改进CGI性能的FasgCGI。FastCGI也被许多脚本语言所支持，PHP-FPM是一个PHP FastCGI管理器。
Java有专用的Servlet规范，WSGI的实现受Servlet的启发比较大。
>在WSGI中有两种角色：一方称之为server或者gateway, 另一方称之为application或者framework。application可以提供一个可调用对象供server调用。
server负责接收HTTP请求，根据请求数据组装environ，定义start_response函数，然后调用application提供的可调用对象，将这两个参数提供给application。application根据environ信息执行业务逻辑，调用的结果会被封装成HTTP响应后发送给客户端。
WSGI对application的要求有3个：
   - 实现一个可调用对象
   - 可调用对象接收两个参数，environ（一个dict，包含WSGI的环境信息）与start_response（一个响应请求的函数）
   - 返回一个iterable可迭代对象

>Django、Flask 遵循WSGI，后端使用werkzeug,除了选择现有的web框架,我们也可以选择werkzeug来实现简短的web框架。
>这里重点使用python自带wsgiref库，实现带路由功能的application,这可以用于简单快速的开发测试。
>也可以使用python自带库，通过一行命令启动一个web服务做文件下载。

``` python3 -m http.server 8000 --bind 127.0.0.1

```
import http.server
import socketserver

PORT = 8000

Handler = http.server.SimpleHTTPRequestHandler
with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print("serving at port", PORT)
    httpd.serve_forever()



