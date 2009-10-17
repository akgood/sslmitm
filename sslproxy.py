import event
import ssl
import socket
import traceback
import errno
import signal

certfile = "testcert2-full.cert"
keyfile = "privkey2.pem"
cafile = "ca-cert.pem"
dest_host = "mail.google.com"
dest_port = 443
listen_port = 12345
recvbuf_max = 32768

def handler(func):
    """ pyevent apparently doesn't do a good job of exception
    handling; specifically if an exception gets thrown and
    propagates back through the dispatch loop, you don't get a
    useful backtrace. So, here's a function decorator to help
    that

    Probably, it would be better to just fix pyevent"""

    def wrapped_func(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except Exception, e:
            traceback.print_exc()
            raise
    return wrapped_func

class Buffer:
    """ Simple class to act as a FIFO-ish data buffer"""

    def __init__(self):
        self._buf = ""

    def push(self, str):
        """ Add data to the end of the buffer """
        self._buf += str

    def pop(self, count):
        """ Remove data from the beginning of the buffer
            Note: does not return anything """
        self._buf = self._buf[count:]

    def get(self):
        """ Get the contents of the buffer """
        return self._buf

    def len(self):
        """ Return the length of the buffer """
        return len(self._buf)

class ProxyHalf:
    """ Represents a single ssl connection (out of a pair that gets
    established for each proxied-connection instance) """

    def __init__(self, recv_buf, send_buf, ssl_sock=None):
        """ Constructor """
        self._ssl_sock = ssl_sock
        self._read_buf = recv_buf
        self._write_buf = send_buf
        self._counterpart = None
        self._read_hdler = None
        self._write_hdler = None

    def set_ssl_sock(self, ssl_sock):
        """ Assign the ssl socket """
        self._ssl_sock = ssl_sock

    def set_counterpart(self, counterpart):
        """ Set the counterpart of the proxy connection (i.e. its
        other half)"""
        self._counterpart = counterpart

    def start(self, start_read=True):
        """ Begin scheduling events to handle data on the socket """
        if start_read:
            self._read_hdler = event.read(self._ssl_sock, self.handshake)
        else:
            self._write_hdler = event.write(self._ssl_sock, self.handshake)

    def notify_write(self):
        """ Set a read event on the socket, if one doesn't already
        exist. Used by the counterpart to notify that data is
        available for writing """
        if self._ssl_sock == None:
            return
        if self._write_buf.len() > 0:
            self._write_hdler = event.write(self._ssl_sock, self._write_data)

    @handler
    def close(self):
        """ Clear handlers and close the socket """
        self._clear_hdlers()
        if (self._ssl_sock):
            try:
                self._ssl_sock.close()
            except Exception, e:
                traceback.print_exc()

    def _ssl_handler(func):
        """ Function wrapper to reschedule the function if a
        non-blocking error occurs """
        def wrapped_func(self, *args):
            try:
                func(self, *args)
            except ssl.SSLError, err:
                self._clear_hdlers()
                if err.args[0] == ssl.SSL_ERROR_WANT_READ:
                    self._read_hdler = event.read(self._ssl_sock, wrapped_func, self, *args)
                elif err.args[0] == ssl.SSL_ERROR_WANT_WRITE:
                    self._write_hdler = event.write(self._ssl_sock, wrapped_func, self, *args)
                else:
                    traceback.print_exc()
                    self.close()
                    self._counterpart.close()
            except Exception, err:
                traceback.print_exc()
                raise
        return wrapped_func

    def _clear_hdlers(self):
        """ Clear event handlers """
        self._clear_read();
        self._clear_write();

    def _clear_read(self):
        """ Clear the read handler """
        if self._read_hdler:
            self._read_hdler.delete()
            self._read_hdler = None

    def _clear_write(self):
        """ Clear the write handler """
        if self._write_hdler:
            self._write_hdler.delete()
            self._write_hdler = None

    @_ssl_handler
    def handshake(self):
        """ Do the ssl handshake """
        self._ssl_sock.do_handshake()
        self._reschedule()

    @_ssl_handler
    def _read_data(self):
        """ Handle data available from the socket """
        in_data = self._ssl_sock.read(1024)
        if (len(in_data) == 0):
            # remote host closed the connection
            self.close()
            return
        self._read_buf.push(in_data)
        self._reschedule()
        self._counterpart.notify_write()

    @_ssl_handler
    def _write_data(self):
        """ Send data when the socket is write-ready """
        len = self._ssl_sock.write(self._write_buf.get())
        self._write_buf.pop(len)
        self._reschedule()

    @handler
    def _reschedule(self):
        self._clear_hdlers()
        if self._write_buf.len() > 0:
            self._write_hdler = event.write(self._ssl_sock, self._write_data)
        if self._read_buf.len() < recvbuf_max:
            self._read_hdler = event.read(self._ssl_sock, self._read_data)

class ProxyConnection:
    """ Represents a proxied connection """

    def __init__(self, accept_pair):
        """ Constructor; given a newly-accepted incoming connection,
        begins to establish an outgoing connection to the destination
        server, and sets up all the relevant state (e.g. two ProxyHalf
        instances)"""

        # Wrap the incoming socket as an ssl connection
        (in_sock, src) = accept_pair
        in_sock.setblocking(0)
        in_ssl = ssl.wrap_socket(in_sock,
                                 ssl_version = ssl.PROTOCOL_SSLv23,
                                 certfile = certfile,
                                 keyfile = keyfile,
                                 ca_certs = cafile,
                                 server_side = True,
                                 do_handshake_on_connect = False)

        # Create the buffer objects
        in_buf = Buffer()
        out_buf = Buffer()

        # Create the ProxyHalf objects
        self._in_sstate = ProxyHalf(in_buf, out_buf, in_ssl)
        self._out_sstate = ProxyHalf(out_buf, in_buf)
        self._in_sstate.set_counterpart(self._out_sstate)
        self._out_sstate.set_counterpart(self._in_sstate)
        self._in_sstate.start(True)

        # Create an outgoing connection
        out_sock = socket.socket()
        out_sock.setblocking(0)
        try:
            out_sock.connect((dest_host, dest_port))
        except IOError, e:
            if e.errno != errno.EINPROGRESS:
                raise

        # We can't wrap the outgoing socket with an ssl socket
        # until it's connected, so set an event for that...
        event.write(out_sock, self._connected, out_sock)

    @handler
    def _connected(self, out_sock):
        out_ssl = ssl.wrap_socket(out_sock,
                                  ssl_version = ssl.PROTOCOL_SSLv23,
                                  do_handshake_on_connect = False)
        self._out_sstate.set_ssl_sock(out_ssl)
        self._out_sstate.start(False)

connections = []

def main(argv):
    # initialize libevent
    event.init()

    # set the SIGINT handler
    event.signal(signal.SIGINT, _sigint)

    # create an incoming (listen) socket, and bind
    listen_sock = socket.socket()
    listen_sock.setblocking(0)
    listen_sock.bind(("localhost", listen_port))

    # start listening, set event
    listen_sock.listen(20)
    event.event(listen_read, None, event.EV_READ | event.EV_PERSIST, listen_sock).add()

    # start event loop
    event.dispatch()

@handler
def listen_read(ev, listen_sock, evtype, arg):
    # accept the incoming connection
    accept_pair = listen_sock.accept()
    connections.append(ProxyConnection(accept_pair))

@handler
def _sigint():
    event.abort()

if __name__ == '__main__':
    import sys
    main(sys.argv)
