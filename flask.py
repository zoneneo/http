#!/usr/bin/env python
import os
from functools import update_wrapper
from werkzeug.wrappers import Request, Response
from werkzeug.routing import Map, Rule
from werkzeug.exceptions import HTTPException, NotFound
# from werkzeug.wsgi import SharedDataMiddleware
from werkzeug.utils import redirect
from urllib.parse import urlparse

try:
    import socketserver
    from http.server import BaseHTTPRequestHandler
    from http.server import HTTPServer
except ImportError:
    import SocketServer as socketserver
    from BaseHTTPServer import HTTPServer
    from BaseHTTPServer import BaseHTTPRequestHandler



class DechunkedInput(io.RawIOBase):
    """An input stream that handles Transfer-Encoding 'chunked'"""

    def __init__(self, rfile):
        self._rfile = rfile
        self._done = False
        self._len = 0

    def readable(self):
        return True

    def read_chunk_len(self):
        try:
            line = self._rfile.readline().decode("latin1")
            _len = int(line.strip(), 16)
        except ValueError:
            raise IOError("Invalid chunk header")
        if _len < 0:
            raise IOError("Negative chunk length not allowed")
        return _len

    def readinto(self, buf):
        read = 0
        while not self._done and read < len(buf):
            if self._len == 0:
                # This is the first chunk or we fully consumed the previous
                # one. Read the next length of the next chunk
                self._len = self.read_chunk_len()

            if self._len == 0:
                # Found the final chunk of size 0. The stream is now exhausted,
                # but there is still a final newline that should be consumed
                self._done = True

            if self._len > 0:
                # There is data (left) in this chunk, so append it to the
                # buffer. If this operation fully consumes the chunk, this will
                # reset self._len to 0.
                n = min(len(buf), self._len)
                buf[read : read + n] = self._rfile.read(n)
                self._len -= n
                read += n

            if self._len == 0:
                # Skip the terminating newline of a chunk that has been fully
                # consumed. This also applies to the 0-sized final chunk
                terminator = self._rfile.readline()
                if terminator not in (b"\n", b"\r\n", b"\r"):
                    raise IOError("Missing chunk terminating newline")

        return read


class WSGIRequestHandler(BaseHTTPRequestHandler, object):

    """A request handler that implements WSGI dispatching."""

    @property
    def server_version(self):
        from . import __version__

        return "Werkzeug/" + __version__

    def make_environ(self):
        request_url = url_parse(self.path)

        def shutdown_server():
            self.server.shutdown_signal = True

        url_scheme = "http" if self.server.ssl_context is None else "https"
        if not self.client_address:
            self.client_address = "<local>"
        if isinstance(self.client_address, str):
            self.client_address = (self.client_address, 0)
        else:
            pass

        # If there was no scheme but the path started with two slashes,
        # the first segment may have been incorrectly parsed as the
        # netloc, prepend it to the path again.
        if not request_url.scheme and request_url.netloc:
            path_info = "/%s%s" % (request_url.netloc, request_url.path)
        else:
            path_info = request_url.path

        path_info = url_unquote(path_info)

        environ = {
            "wsgi.version": (1, 0),
            "wsgi.url_scheme": url_scheme,
            "wsgi.input": self.rfile,
            "wsgi.errors": sys.stderr,
            "wsgi.multithread": self.server.multithread,
            "wsgi.multiprocess": self.server.multiprocess,
            "wsgi.run_once": False,
            "werkzeug.server.shutdown": shutdown_server,
            "SERVER_SOFTWARE": self.server_version,
            "REQUEST_METHOD": self.command,
            "SCRIPT_NAME": "",
            "PATH_INFO": wsgi_encoding_dance(path_info),
            "QUERY_STRING": wsgi_encoding_dance(request_url.query),
            # Non-standard, added by mod_wsgi, uWSGI
            "REQUEST_URI": wsgi_encoding_dance(self.path),
            # Non-standard, added by gunicorn
            "RAW_URI": wsgi_encoding_dance(self.path),
            "REMOTE_ADDR": self.address_string(),
            "REMOTE_PORT": self.port_integer(),
            "SERVER_NAME": self.server.server_address[0],
            "SERVER_PORT": str(self.server.server_address[1]),
            "SERVER_PROTOCOL": self.request_version,
        }

        for key, value in self.get_header_items():
            key = key.upper().replace("-", "_")
            value = value.replace("\r\n", "")
            if key not in ("CONTENT_TYPE", "CONTENT_LENGTH"):
                key = "HTTP_" + key
                if key in environ:
                    value = "{},{}".format(environ[key], value)
            environ[key] = value

        if environ.get("HTTP_TRANSFER_ENCODING", "").strip().lower() == "chunked":
            environ["wsgi.input_terminated"] = True
            environ["wsgi.input"] = DechunkedInput(environ["wsgi.input"])

        # Per RFC 2616, if the URL is absolute, use that as the host.
        # We're using "has a scheme" to indicate an absolute URL.
        if request_url.scheme and request_url.netloc:
            environ["HTTP_HOST"] = request_url.netloc

        try:
            # binary_form=False gives nicer information, but wouldn't be compatible with
            # what Nginx or Apache could return.
            peer_cert = self.connection.getpeercert(binary_form=True)
            if peer_cert is not None:
                # Nginx and Apache use PEM format.
                environ["SSL_CLIENT_CERT"] = ssl.DER_cert_to_PEM_cert(peer_cert)
        except ValueError:
            # SSL handshake hasn't finished.
            self.server.log("error", "Cannot fetch SSL peer certificate info")
        except AttributeError:
            # Not using TLS, the socket will not have getpeercert().
            pass

        return environ

    def run_wsgi(self):
        if self.headers.get("Expect", "").lower().strip() == "100-continue":
            self.wfile.write(b"HTTP/1.1 100 Continue\r\n\r\n")

        self.environ = environ = self.make_environ()
        headers_set = []
        headers_sent = []

        def write(data):
            assert headers_set, "write() before start_response"
            if not headers_sent:
                status, response_headers = headers_sent[:] = headers_set
                try:
                    code, msg = status.split(None, 1)
                except ValueError:
                    code, msg = status, ""
                code = int(code)
                self.send_response(code, msg)
                header_keys = set()
                for key, value in response_headers:
                    self.send_header(key, value)
                    key = key.lower()
                    header_keys.add(key)
                if not (
                    "content-length" in header_keys
                    or environ["REQUEST_METHOD"] == "HEAD"
                    or code < 200
                    or code in (204, 304)
                ):
                    self.close_connection = True
                    self.send_header("Connection", "close")
                if "server" not in header_keys:
                    self.send_header("Server", self.version_string())
                if "date" not in header_keys:
                    self.send_header("Date", self.date_time_string())
                self.end_headers()

            assert isinstance(data, bytes), "applications must write bytes"
            if data:
                # Only write data if there is any to avoid Python 3.5 SSL bug
                self.wfile.write(data)
            self.wfile.flush()

        def start_response(status, response_headers, exc_info=None):
            if exc_info:
                try:
                    if headers_sent:
                        reraise(*exc_info)
                finally:
                    exc_info = None
            elif headers_set:
                raise AssertionError("Headers already set")
            headers_set[:] = [status, response_headers]
            return write

        def execute(app):
            application_iter = app(environ, start_response)
            try:
                for data in application_iter:
                    write(data)
                if not headers_sent:
                    write(b"")
            finally:
                if hasattr(application_iter, "close"):
                    application_iter.close()

        try:
            execute(self.server.app)
        except (_ConnectionError, socket.timeout) as e:
            self.connection_dropped(e, environ)
        except Exception:
            if self.server.passthrough_errors:
                raise
            from .debug.tbtools import get_current_traceback

            traceback = get_current_traceback(ignore_system_exceptions=True)
            try:
                # if we haven't yet sent the headers but they are set
                # we roll back to be able to set them again.
                if not headers_sent:
                    del headers_set[:]
                execute(InternalServerError())
            except Exception:
                pass
            self.server.log("error", "Error on request:\n%s", traceback.plaintext)

    def handle(self):
        """Handles a request ignoring dropped connections."""
        try:
            BaseHTTPRequestHandler.handle(self)
        except (_ConnectionError, socket.timeout) as e:
            self.connection_dropped(e)
        except Exception as e:
            if self.server.ssl_context is None or not is_ssl_error(e):
                raise
        if self.server.shutdown_signal:
            self.initiate_shutdown()

    def initiate_shutdown(self):
        """A horrible, horrible way to kill the server for Python 2.6 and
        later.  It's the best we can do.
        """
        # Windows does not provide SIGKILL, go with SIGTERM then.
        sig = getattr(signal, "SIGKILL", signal.SIGTERM)
        # reloader active
        if is_running_from_reloader():
            os.kill(os.getpid(), sig)
        # python 2.7
        self.server._BaseServer__shutdown_request = True
        # python 2.6
        self.server._BaseServer__serving = False

    def connection_dropped(self, error, environ=None):
        """Called if the connection was closed by the client.  By default
        nothing happens.
        """

    def handle_one_request(self):
        """Handle a single HTTP request."""
        self.raw_requestline = self.rfile.readline()
        if not self.raw_requestline:
            self.close_connection = 1
        elif self.parse_request():
            return self.run_wsgi()

    def send_response(self, code, message=None):
        """Send the response header and log the response code."""
        self.log_request(code)
        if message is None:
            message = code in self.responses and self.responses[code][0] or ""
        if self.request_version != "HTTP/0.9":
            hdr = "%s %d %s\r\n" % (self.protocol_version, code, message)
            self.wfile.write(hdr.encode("ascii"))

    def version_string(self):
        return BaseHTTPRequestHandler.version_string(self).strip()

    def address_string(self):
        if getattr(self, "environ", None):
            return self.environ["REMOTE_ADDR"]
        elif not self.client_address:
            return "<local>"
        elif isinstance(self.client_address, str):
            return self.client_address
        else:
            return self.client_address[0]

    def port_integer(self):
        return self.client_address[1]

    def log_request(self, code="-", size="-"):
        try:
            path = uri_to_iri(self.path)
            msg = "%s %s %s" % (self.command, path, self.request_version)
        except AttributeError:
            # path isn't set if the requestline was bad
            msg = self.requestline

        code = str(code)

        if click:
            color = click.style

            if code[0] == "1":  # 1xx - Informational
                msg = color(msg, bold=True)
            elif code[0] == "2":  # 2xx - Success
                msg = color(msg, fg="white")
            elif code == "304":  # 304 - Resource Not Modified
                msg = color(msg, fg="cyan")
            elif code[0] == "3":  # 3xx - Redirection
                msg = color(msg, fg="green")
            elif code == "404":  # 404 - Resource Not Found
                msg = color(msg, fg="yellow")
            elif code[0] == "4":  # 4xx - Client Error
                msg = color(msg, fg="red", bold=True)
            else:  # 5xx, or any other response
                msg = color(msg, fg="magenta", bold=True)

        self.log("info", '"%s" %s %s', msg, code, size)

    def log_error(self, *args):
        self.log("error", *args)

    def log_message(self, format, *args):
        self.log("info", format, *args)

    def log(self, type, message, *args):
        _log(
            type,
            "%s - - [%s] %s\n"
            % (self.address_string(), self.log_date_time_string(), message % args),
        )

    def get_header_items(self):
        """
        Get an iterable list of key/value pairs representing headers.

        This function provides Python 2/3 compatibility as related to the
        parsing of request headers. Python 2.7 is not compliant with
        RFC 3875 Section 4.1.18 which requires multiple values for headers
        to be provided or RFC 2616 which allows for folding of multi-line
        headers. This function will return a matching list regardless
        of Python version. It can be removed once Python 2.7 support
        is dropped.

        :return: List of tuples containing header hey/value pairs
        """
        if PY2:
            # For Python 2, process the headers manually according to
            # W3C RFC 2616 Section 4.2.
            items = []
            for header in self.headers.headers:
                # Remove "\r\n" from the header and split on ":" to get
                # the field name and value.
                try:
                    key, value = header[0:-2].split(":", 1)
                except ValueError:
                    # If header could not be slit with : but starts with white
                    # space and it follows an existing header, it's a folded
                    # header.
                    if header[0] in ("\t", " ") and items:
                        # Pop off the last header
                        key, value = items.pop()
                        # Append the current header to the value of the last
                        # header which will be placed back on the end of the
                        # list
                        value = value + header
                    # Otherwise it's just a bad header and should error
                    else:
                        # Re-raise the value error
                        raise

                # Add the key and the value once stripped of leading
                # white space. The specification allows for stripping
                # trailing white space but the Python 3 code does not
                # strip trailing white space. Therefore, trailing space
                # will be left as is to match the Python 3 behavior.
                items.append((key, value.lstrip()))
        else:
            items = self.headers.items()

        return items


class BaseWSGIServer(HTTPServer, object):

    """Simple single-threaded, single-process WSGI server."""

    multithread = False
    multiprocess = False
    request_queue_size = LISTEN_QUEUE

    def __init__(
        self,
        host,
        port,
        app,
        handler=None,
        passthrough_errors=False,
        ssl_context=None,
        fd=None,
    ):
        if handler is None:
            handler = WSGIRequestHandler

        self.address_family = select_address_family(host, port)

        if fd is not None:
            real_sock = socket.fromfd(fd, self.address_family, socket.SOCK_STREAM)
            port = 0

        server_address = get_sockaddr(host, int(port), self.address_family)

        # remove socket file if it already exists
        if self.address_family == af_unix and os.path.exists(server_address):
            os.unlink(server_address)
        HTTPServer.__init__(self, server_address, handler)

        self.app = app
        self.passthrough_errors = passthrough_errors
        self.shutdown_signal = False
        self.host = host
        self.port = self.socket.getsockname()[1]

        # Patch in the original socket.
        if fd is not None:
            self.socket.close()
            self.socket = real_sock
            self.server_address = self.socket.getsockname()

        if ssl_context is not None:
            if isinstance(ssl_context, tuple):
                ssl_context = load_ssl_context(*ssl_context)
            if ssl_context == "adhoc":
                ssl_context = generate_adhoc_ssl_context()

            # If we are on Python 2 the return value from socket.fromfd
            # is an internal socket object but what we need for ssl wrap
            # is the wrapper around it :(
            sock = self.socket
            if PY2 and not isinstance(sock, socket.socket):
                sock = socket.socket(sock.family, sock.type, sock.proto, sock)
            self.socket = ssl_context.wrap_socket(sock, server_side=True)
            self.ssl_context = ssl_context
        else:
            self.ssl_context = None

    def log(self, type, message, *args):
        _log(type, message, *args)

    def serve_forever(self):
        self.shutdown_signal = False
        try:
            HTTPServer.serve_forever(self)
        except KeyboardInterrupt:
            pass
        finally:
            self.server_close()

    def handle_error(self, request, client_address):
        if self.passthrough_errors:
            raise
        # Python 2 still causes a socket.error after the earlier
        # handling, so silence it here.
        if isinstance(sys.exc_info()[1], _ConnectionError):
            return
        return HTTPServer.handle_error(self, request, client_address)

    def get_request(self):
        con, info = self.socket.accept()
        return con, info

def make_server(
    host=None,
    port=None,
    app=None,
    threaded=False,
    processes=1,
    request_handler=None,
    passthrough_errors=False,
    ssl_context=None,
    fd=None,
):
    if threaded and processes > 1:
        raise ValueError("cannot have a multithreaded and multi process server.")
    else:
        return BaseWSGIServer(
            host, port, app, request_handler, passthrough_errors, ssl_context, fd=fd
        )

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
            # srv = make_server(
            #     hostname,
            #     port,
            #     application,
            #     threaded,
            #     processes,
            #     request_handler,
            #     passthrough_errors,
            #     ssl_context,
            #     fd=fd,
            # )
            srv = make_server(host, port, self, **options)
            srv.serve_forever()

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
