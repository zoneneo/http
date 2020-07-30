#!/usr/bin/env python
import os
import io
import json
from urllib.parse import urlparse
from wsgiref.util import setup_testing_defaults
from wsgiref.simple_server import make_server

from wsgiref.simple_server import make_server, demo_app

class Shortly(object):

    def __init__(self):
        self.url_map = {}

    # def dispatch_request(self, request):
    #     adapter = self.url_map.bind_to_environ(request.environ)
    #     try:
    #         endpoint, values = adapter.match()
    #         #return getattr(self, 'on_' + endpoint)(request, **values)
    #         return json.dumps({'endpoint':endpoint,'values':values})
    #     except Exception as e:
    #         return e


    # def wsgi_app(self, environ, start_response):
    #     request = Request(environ)
    #     response = self.dispatch_request(request)
    #     return response(environ, start_response)



    def dispatch_request(self):
        req = _request_ctx_stack.top.request
        if req.routing_exception is not None:
            self.raise_routing_exception(req)
        rule = req.url_rule
        # if we provide automatic options for this URL and the
        # request came with the OPTIONS method, reply automatically
        if (
            getattr(rule, "provide_automatic_options", False)
            and req.method == "OPTIONS"
        ):
            return self.make_default_options_response()
        # otherwise dispatch to the handler for that endpoint
        return self.view_functions[rule.endpoint](**req.view_args)

    # def wsgi_app(self,environ, start_response):
    #     setup_testing_defaults(environ)
    #     if environ['REQUEST_METHOD'] == 'GET':
    #         status = '200 OK'
    #         headers = [('Content-type', 'text/plain')]
    #         start_response(status, headers)

    #         ret = ["%s: %s\n" % (key, value) for key, value in environ.iteritems()]
    #         return ret
    #     else:
    #         status = '200 OK'
    #         headers = [('Content-type', 'text/plain')]

    #         try:
    #             length = int(environ.get('CONTENT_LENGTH', '0'))
    #         except ValueError:
    #             length = 0
    #         if length != 0:
    #             body = environ['wsgi.input'].read(length)
    #             print(body)

    #         response_body = json.dumps(body).encode('utf-8')
    #         headers = [('Content-Type', 'application/json'), ('Content-Length', str(len(response_body)))]
    #         start_response(status, headers)
    #         return body


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

    def full_dispatch_request(self):
        """Dispatches the request and on top of that performs request
        pre and postprocessing as well as HTTP exception catching and
        error handling.

        .. versionadded:: 0.7
        """
        self.try_trigger_before_first_request_functions()
        try:
            request_started.send(self)
            rv = self.preprocess_request()
            if rv is None:
                rv = self.dispatch_request()
        except Exception as e:
            rv = self.handle_user_exception(e)
        return self.finalize_request(rv)

    def wsgi_app(self, environ, start_response):
        ctx = self.request_context(environ)
        error = None
        try:
            try:
                ctx.push()
                response = self.full_dispatch_request()
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



if __name__ == '__main__':
    PORT=8001
    app=Shortly()
    httpd = make_server('', PORT, app)
    print("Serving HTTP on port",PORT)
    httpd.serve_forever()