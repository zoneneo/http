#/usr/bin/env python3

from urllib import request
from urllib import parse 



#基本的网络请求示例
#params = parse.urlencode({'spam': 1, 'eggs': 2, 'bacon': 0})
#f = request.urlopen("http://www.musi-cal.com/cgi-bin/query?%s" % params)
#
# resu = urllib.request.urlopen('http://www.baidu.com', data = None, timeout = 10)
# print(resu.read(300))

# req = request.Request(url='http://localhost:8000', data=b'some data',method='PUT')
# f = request.urlopen(req)
# print(f.status)
# print(f.reason)

#添加 http headers
# req = request.Request('http://www.example.com/')
# req.add_header('Referer', 'http://www.python.org/')
# r = urllib.request.urlopen(req)

#添加 user-agent
# opener = request.build_opener()
# opener.addheaders = [('User-agent', 'Mozilla/5.0')]
# opener.open('http://www.example.com/')

# 指定代理方式请求
# opener = request.FancyURLopener({'http': 'http://proxy.example.com/'})
# f = opener.open("http://www.python.org")



headers = { 
'Accept':'application/json, text/plain, */*',
'Accept-Encoding':'gzip, deflate',    
'Accept-Language':'zh-CN,zh;q=0.8',    
'Connection':'keep-alive',    
'Content-Length':'14',  
'Content-Type':'application/x-www-form-urlencoded',    
'Referer':'http://10.1.2.151/',    
'User-Agent':'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.23 Mobile Safari/537.36' 
}

data = parse.urlencode({"id":"wdb","pwd":"wdb"}).encode('utf-8')
url = "http://127.0.0.1:8000/test.html"
req = request.Request(url, headers=headers, data=data, method='POST')  

with request.urlopen(req) as res:
	if res.status:
		page = res.read().decode('utf-8')
		print(page)
	else:
		print(res.reason)
    

