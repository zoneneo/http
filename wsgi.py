#!/usr/bin/env python
import os
import io
import json
# from urllib.parse import urlparse
from wsgiref.util import setup_testing_defaults
# from wsgiref.simple_server import make_server
from threading import Lock
import sys
import mimetypes
from wsgiref import simple_server, util
from wsgiref.headers import Headers

class DotDict(dict):
    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        self.__dict__ = self


class RuleFactory(object):
    def get_rules(self, map):
        raise NotImplementedError()

class Rule(RuleFactory):
    def __init__(
            self,
            string,
            defaults=None,
            methods=None,
            endpoint=None
    ):
        if not string.startswith("/"):
            raise ValueError("urls must start with a leading slash")
        self.rule = string
        self.is_leaf = not string.endswith("/")
        self.map = None

        if methods is not None:
            if isinstance(methods, str):
                raise TypeError("'methods' should be a list of strings.")

            methods = {x.upper() for x in methods}

            if "HEAD" not in methods and "GET" in methods:
                methods.add("HEAD")

        self.methods = methods
        self.endpoint = endpoint

        if defaults:
            self.arguments = set(map(str, defaults))
        else:
            self.arguments = set()

    def get_rules(self, map):
        yield self

    def refresh(self):
        """Rebinds and refreshes the URL.  Call this if you modified the
        rule in place.

        :internal:
        """
        self.bind(self.map, rebind=True)

    def bind(self, map, rebind=False):
        """Bind the url to a map and create a regular expression based on
        the information from the rule itself and the defaults from the map.

        :internal:
        """
        if self.map is not None and not rebind:
            raise RuntimeError("url rule %r already bound to map %r" % (self, self.map))
        self.map = map
        if self.strict_slashes is None:
            self.strict_slashes = map.strict_slashes
        if self.merge_slashes is None:
            self.merge_slashes = map.merge_slashes
        if self.subdomain is None:
            self.subdomain = map.default_subdomain
        self.compile()

    def compile(self):
        """Compiles the regular expression and stores it."""
        assert self.map is not None, "rule not bound"

        if self.map.host_matching:
            domain_rule = self.host or ""
        else:
            domain_rule = self.subdomain or ""

        self._trace = []
        self._converters = {}
        self._static_weights = []
        self._argument_weights = []
        regex_parts = []

        def _build_regex(rule):
            index = 0
            for converter, arguments, variable in parse_rule(rule):
                if converter is None:
                    for match in re.finditer(r"/+|[^/]+", variable):
                        part = match.group(0)
                        if part.startswith("/"):
                            if self.merge_slashes:
                                regex_parts.append(r"/+?")
                                self._trace.append((False, "/"))
                            else:
                                regex_parts.append(part)
                                self._trace.append((False, part))
                            continue
                        self._trace.append((False, part))
                        regex_parts.append(re.escape(part))
                        if part:
                            self._static_weights.append((index, -len(part)))
                else:
                    if arguments:
                        c_args, c_kwargs = parse_converter_args(arguments)
                    else:
                        c_args = ()
                        c_kwargs = {}
                    convobj = self.get_converter(variable, converter, c_args, c_kwargs)
                    regex_parts.append("(?P<%s>%s)" % (variable, convobj.regex))
                    self._converters[variable] = convobj
                    self._trace.append((True, variable))
                    self._argument_weights.append(convobj.weight)
                    self.arguments.add(str(variable))
                index = index + 1

        _build_regex(domain_rule)
        regex_parts.append("\\|")
        self._trace.append((False, "|"))
        _build_regex(self.rule if self.is_leaf else self.rule.rstrip("/"))
        if not self.is_leaf:
            self._trace.append((False, "/"))

        self._build = self._compile_builder(False).__get__(self, None)
        self._build_unknown = self._compile_builder(True).__get__(self, None)

        if self.build_only:
            return

        if not (self.is_leaf and self.strict_slashes):
            reps = u"*" if self.merge_slashes else u"?"
            tail = u"(?<!/)(?P<__suffix__>/%s)" % reps
        else:
            tail = u""

        regex = u"^%s%s$" % (u"".join(regex_parts), tail)
        self._regex = re.compile(regex, re.UNICODE)



class Map(object):
    lock_class = Lock

    def __init__(
        self,
        rules=None,
        charset="utf-8",
        strict_slashes=True,
        merge_slashes=True,
        redirect_defaults=True,
        converters=None,
        sort_parameters=False,
        sort_key=None,
        encoding_errors="replace",
        host_matching=False,
    ):
        self._rules = []
        self._rules_by_endpoint = {}
        self._remap = True
        self._remap_lock = self.lock_class()

        self.charset = charset
        self.encoding_errors = encoding_errors
        self.strict_slashes = strict_slashes
        self.merge_slashes = merge_slashes
        self.redirect_defaults = redirect_defaults
        self.host_matching = host_matching

        self.converters = self.default_converters.copy()
        if converters:
            self.converters.update(converters)

        self.sort_parameters = sort_parameters
        self.sort_key = sort_key

        for rulefactory in rules or ():
            self.add(rulefactory)

    def is_endpoint_expecting(self, endpoint, *arguments):
        """Iterate over all rules and check if the endpoint expects
        the arguments provided.  This is for example useful if you have
        some URLs that expect a language code and others that do not and
        you want to wrap the builder a bit so that the current language
        code is automatically added if not provided but endpoints expect
        it.

        :param endpoint: the endpoint to check.
        :param arguments: this function accepts one or more arguments
                          as positional arguments.  Each one of them is
                          checked.
        """
        self.update()
        arguments = set(arguments)
        for rule in self._rules_by_endpoint[endpoint]:
            if arguments.issubset(rule.arguments):
                return True
        return False

    def iter_rules(self, endpoint=None):
        """Iterate over all rules or the rules of an endpoint.

        :param endpoint: if provided only the rules for that endpoint
                         are returned.
        :return: an iterator
        """
        self.update()
        if endpoint is not None:
            return iter(self._rules_by_endpoint[endpoint])
        return iter(self._rules)

    def add(self, rulefactory):
        """Add a new rule or factory to the map and bind it.  Requires that the
        rule is not bound to another map.

        :param rulefactory: a :class:`Rule` or :class:`RuleFactory`
        """
        for rule in rulefactory.get_rules(self):
            rule.bind(self)
            self._rules.append(rule)
            self._rules_by_endpoint.setdefault(rule.endpoint, []).append(rule)
        self._remap = True

    def bind(
        self,
        server_name,
        script_name=None,
        subdomain=None,
        url_scheme="http",
        default_method="GET",
        path_info=None,
        query_args=None,
    ):
        """Return a new :class:`MapAdapter` with the details specified to the
        call.  Note that `script_name` will default to ``'/'`` if not further
        specified or `None`.  The `server_name` at least is a requirement
        because the HTTP RFC requires absolute URLs for redirects and so all
        redirect exceptions raised by Werkzeug will contain the full canonical
        URL.

        If no path_info is passed to :meth:`match` it will use the default path
        info passed to bind.  While this doesn't really make sense for
        manual bind calls, it's useful if you bind a map to a WSGI
        environment which already contains the path info.

        `subdomain` will default to the `default_subdomain` for this map if
        no defined. If there is no `default_subdomain` you cannot use the
        subdomain feature.

        .. versionchanged:: 1.0
            If ``url_scheme`` is ``ws`` or ``wss``, only WebSocket rules
            will match.

        .. versionchanged:: 0.15
            ``path_info`` defaults to ``'/'`` if ``None``.

        .. versionchanged:: 0.8
            ``query_args`` can be a string.

        .. versionchanged:: 0.7
            Added ``query_args``.
        """
        server_name = server_name.lower()
        if self.host_matching:
            if subdomain is not None:
                raise RuntimeError("host matching enabled and a subdomain was provided")
        elif subdomain is None:
            subdomain = self.default_subdomain
        if script_name is None:
            script_name = "/"
        if path_info is None:
            path_info = "/"
        try:
            server_name = _encode_idna(server_name)
        except UnicodeError:
            raise BadHost()
        return MapAdapter(
            self,
            server_name,
            script_name,
            subdomain,
            url_scheme,
            path_info,
            default_method,
            query_args,
        )


    def update(self):
        """Called before matching and building to keep the compiled rules
        in the correct order after things changed.
        """
        if not self._remap:
            return

        with self._remap_lock:
            if not self._remap:
                return

            self._rules.sort(key=lambda x: x.match_compare_key())
            for rules in itervalues(self._rules_by_endpoint):
                rules.sort(key=lambda x: x.build_compare_key())
            self._remap = False

    def __repr__(self):
        rules = self.iter_rules()
        return "%s(%s)" % (self.__class__.__name__, list(rules))


def _endpoint_from_view_func(view_func):
    """Internal helper that returns the default endpoint for a given
    function.  This always is the function name.
    """
    assert view_func is not None, "expected view func if endpoint is not provided."
    return view_func.__name__

class Shortly(object):

    def __init__(self):
        self.url_map = {}
        self.view_functions = {}
        self.headers=Headers()
        self.status=None


    def add_url_rule(self, rule, endpoint=None, view_func=None, **options ):
        if endpoint is None:
            endpoint = _endpoint_from_view_func(view_func)
        options["endpoint"] = endpoint
        methods = options.pop("methods", None)

        # if the methods are not given and the view_func object knows its
        # methods we can use that instead.  If neither exists, we go with
        # a tuple of only ``GET`` as default.
        if methods is None:
            methods = getattr(view_func, "methods", None) or ("GET",)
        if isinstance(methods, str):
            raise TypeError(
                "Allowed methods have to be iterables of strings, "
                'for example: @app.route(..., methods=["POST"])'
            )
        methods = set(item.upper() for item in methods)

        rule = Rule(rule, methods=methods, **options)


        self.url_map.add(rule)
        if view_func is not None:
            self.view_functions[endpoint] = view_func

    def route(self, rule, **options):
        def decorator(f):
            endpoint = options.pop("endpoint", None)
            self.add_url_rule(rule, endpoint, f, **options)
            return f

        return decorator

    def request_context(self, environ):
        """
        :param environ: a WSGI environment
        """
        request=DotDict()
        request.scheme = util.guess_scheme(environ)
        request.uri = util.request_uri(environ)
        request.address = util.application_uri(environ)
        request.path= util.shift_path_info(environ)
        if environ.get('REQUEST_METHOD',None):
            request.method=environ['REQUEST_METHOD']

        if environ.get('CONTENT_TYPE',None):
            self.headers.add_header('CONTENT_TYPE', environ['CONTENT_TYPE'])

        try:
            length = int(environ.get('CONTENT_LENGTH', '0'))
            request.body = environ['wsgi.input'].read(length)
        except ValueError:
            request.body = b''
        return request

    def dispatch_request(self,request):

        if request.path.startswith('/static'):
            fn = os.path.join(path, request.path[1:])
            if '.' not in fn.split(os.path.sep)[-1]:
                fn = os.path.join(fn, 'index.html')
            type = mimetypes.guess_type(fn)[0]

            if os.path.exists(fn):
                self.status = '200 OK'
                self.headers.add_header('Content-type', type)
                return util.FileWrapper(open(fn, "rb"))
            else:
                self.status = '404 Not Found'
                self.headers.add_header('Content-type', 'text/plain')
                return [b'not found']

        try:

            self.status = '200 OK'
            body=json.loads(request.body.decode('utf-8'))
            #rule = request.url_rule
            #return self.view_functions[rule.endpoint](**req.view_args)
            return body
        except Exception as e:
            self.status = '500 server error'
            return str(e)



    def wsgi_app(self, environ, start_response):
        ctx = self.request_context(environ)
        try:
            try:
                response = self.dispatch_request(ctx)
                headers=[(k,v) for k,v in self.headers.items()]
                start_response(self.status, headers)
                return response
            except Exception as e:
                start_response('500 server error', [('Content-type', 'text/plain')])
                return [str(e)]
        finally:
            pass
            
    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)



if __name__ == '__main__':
    app=Shortly()
    path = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
    httpd = simple_server.make_server('', port, app)
    print("Serving {} on port {}, control-C to stop".format(path, port))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down.")
        httpd.server_close()
