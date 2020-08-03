#!/usr/bin/env python
import os
import io
import json
# from urllib.parse import urlparse
from wsgiref.util import setup_testing_defaults
# from wsgiref.simple_server import make_server

import sys
import mimetypes
from wsgiref import simple_server, util


class Shortly(object):

    def __init__(self):
        self.url_map = {}

    def dispatch_request(self):
        req = _request_ctx_stack.top.request
        if req.routing_exception is not None:
            self.raise_routing_exception(req)
        rule = req.url_rule
        return self.view_functions[rule.endpoint](**req.view_args)

    def wsgi_app(self,environ, start_response):
        setup_testing_defaults(environ)
        if environ['REQUEST_METHOD'] == 'GET':
            status = '200 OK'
            headers = [('Content-type', 'text/plain')]
            start_response(status, headers)

            ret = ["%s: %s\n" % (key, value) for key, value in environ.iteritems()]
            return ret
        else:
            status = '200 OK'
            headers = [('Content-type', 'text/plain')]

            try:
                length = int(environ.get('CONTENT_LENGTH', '0'))
            except ValueError:
                length = 0
            if length != 0:
                body = environ['wsgi.input'].read(length)
                print(body)

            response_body = json.dumps(body).encode('utf-8')
            headers = [('Content-Type', 'application/json'), ('Content-Length', str(len(response_body)))]
            start_response(status, headers)
            return body


    def request_context(self, environ):
        """Create a :class:`~flask.ctx.RequestContext` representing a
        WSGI environment. Use a ``with`` block to push the context,
        which will make :data:`request` point at this request.

        See :doc:`/reqcontext`.

        Typically you should not call this from your own code. A request
        context is automatically pushed by the :meth:`wsgi_app` when
        handling a request. Use :meth:`test_request_context` to create
        an environment and context instead of this method.

        :param environ: a WSGI environment
        """
        return RequestContext(self, environ)



    def wsgi_app(self, environ, start_response):
        ctx = self.request_context(environ)
        error = None
        try:
            try:
                ctx.push()
                response = self.dispatch_request()
            except Exception as e:
                error = e
                response = self.handle_exception(e)
            except:  # noqa: B001
                error = sys.exc_info()[1]
                raise
            return response(environ, start_response)
        finally:
            if self.should_ignore_error(error):
                error = None
            ctx.auto_pop(error)

            
    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)


def app(environ, respond):

    fn = os.path.join(path, environ['PATH_INFO'][1:])
    if '.' not in fn.split(os.path.sep)[-1]:
        fn = os.path.join(fn, 'index.html')
    type = mimetypes.guess_type(fn)[0]

    if os.path.exists(fn):
        respond('200 OK', [('Content-Type', type)])
        return util.FileWrapper(open(fn, "rb"))
    else:
        respond('404 Not Found', [('Content-Type', 'text/plain')])
        return [b'not found']




if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
    httpd = simple_server.make_server('', port, app)
    print("Serving {} on port {}, control-C to stop".format(path, port))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down.")
        httpd.server_close()
