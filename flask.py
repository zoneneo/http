#!/usr/bin/env python
import os
from functools import update_wrapper
from werkzeug.wrappers import Request, Response
from werkzeug.routing import Map, Rule
from werkzeug.exceptions import HTTPException, NotFound
# from werkzeug.wsgi import SharedDataMiddleware
from werkzeug.utils import redirect
from urllib.parse import urlparse


def _endpoint_from_view_func(view_func):
    """Internal helper that returns the default endpoint for a given
    function.  This always is the function name.
    """
    assert view_func is not None, "expected view func if endpoint is not provided."
    return view_func.__name__

def setupmethod(f):
    """Wraps a method so that it performs a check in debug mode if the
    first request was already handled.
    """

#Map的作用则是保存所有Rule对象。werkzeug库中的Map与Rule在Flask中的应用
class Flask(object):

    def __init__(self):
        # template_path = os.path.join(os.path.dirname(__file__), 'templates')
        # self.jinja_env = Environment(loader=FileSystemLoader(template_path), autoescape=True)
        # self.url_map = Map([
        # Rule('/', endpoint='new_url'),
        # Rule('/<short_id>', endpoint='follow_short_link'),
        # Rule('/<short_id>+', endpoint='short_link_details')
        # ])
        self.debug=True
        self.url_rule_class = Rule
        self.url_map_class = Map
        self.url_map = self.url_map_class()
        self.view_functions = {}
        self._got_first_request =True

    def endpoint(self, endpoint):
        def decorator(f):
            self.view_functions[endpoint] = f
            return f

        return decorator


    def add_url_rule(
        self,
        rule,
        endpoint=None,
        view_func=None,
        provide_automatic_options=None,
        **options
    ):
        if endpoint is None:
            endpoint = _endpoint_from_view_func(view_func)
        options["endpoint"] = endpoint
        methods = options.pop("methods", None)

        # if the methods are not given and the view_func object knows its
        # methods we can use that instead.  If neither exists, we go with
        # a tuple of only ``GET`` as default.
        if methods is None:
            methods = getattr(view_func, "methods", None) or ("GET",)
        if isinstance(methods, str):#string_types
            raise TypeError(
                "Allowed methods have to be iterables of strings, "
                'for example: @app.route(..., methods=["POST"])'
            )
        methods = set(item.upper() for item in methods)

        # Methods that should always be added
        required_methods = set(getattr(view_func, "required_methods", ()))

        # starting with Flask 0.8 the view_func object can disable and
        # force-enable the automatic options handling.
        if provide_automatic_options is None:
            provide_automatic_options = getattr(
                view_func, "provide_automatic_options", None
            )

        if provide_automatic_options is None:
            if "OPTIONS" not in methods:
                provide_automatic_options = True
                required_methods.add("OPTIONS")
            else:
                provide_automatic_options = False

        # Add the required methods now.
        methods |= required_methods

        rule = self.url_rule_class(rule, methods=methods, **options)
        rule.provide_automatic_options = provide_automatic_options

        self.url_map.add(rule)
        if view_func is not None:
            # old_func = self.view_functions.get(endpoint)
            # if old_func is not None and old_func != view_func:
            #     raise AssertionError(
            #         "View function mapping is overwriting an "
            #         "existing endpoint function: %s" % endpoint
            #     )
            self.view_functions[endpoint] = view_func


    def route(self, rule, **options):
        def decorator(f):
            endpoint = options.pop("endpoint", None)
            self.add_url_rule(rule, endpoint, f, **options)
            return f

        return decorator


    def render_template(self, template_name, **context):
        t = self.jinja_env.get_template(template_name)
        return Response(t.render(context), mimetype='text/html')


    def dispatch_request(self, request):
        adapter = self.url_map.bind_to_environ(request.environ)
        try:
            endpoint, values = adapter.match()
            #return getattr(self, 'on_' + endpoint)(request, **values)
            return self.view_functions.get(endpoint)(request, **values)
        except HTTPException as e:
            return e


    def wsgi_app(self, environ, start_response):
        request = Request(environ)
        response = self.dispatch_request(request)
        return response(environ, start_response)


    def run(self, host=None, port=None, debug=None, load_dotenv=True, **options):
        from werkzeug.serving import run_simple
        try:
            run_simple(host, port, self, **options)
        finally:
            self._got_first_request = False


    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)

app = Flask()


@app.route('/api/user',methods=['GET'])
def get_user():
    user={'name':'admin','email':'test@exmple.com'}
    return json.dumps(user)

@app.route('/api/user',methods=['POST'])
def add_user():
    msg={'status':'200','message':'ok','data':params}
    return json.dumps(msg)



if __name__ == '__main__':
    app.run('127.0.0.1', 6000, app, use_debugger=True, use_reloader=True)
