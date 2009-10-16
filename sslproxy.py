import event
import ssl
import socket
import traceback
import errno

certfile = "testcert2-full.cert"
keyfile = "privkey2.pem"
cafile = "cafile.pem"
dest_host = "mail.google.com"
dest_port = 443
listen_port = 12345
recvbuf_max = 32768

def handler(func):
    def wrapped_func(*args, **kwargs):
        try:
            print func, args, kwargs
            func(*args, **kwargs)
        except Exception, e:
            traceback.print_exc()
            raise
    return wrapped_func

class Buffer:
    """ Exists for the sole purpose of providing indirection """
    def __init__(self, str):
        self.buf = str

class ProxyHalf:
    def ssl_handler(func):
        def wrapped_func(self, *args):
            try:
                print func, self, args
                func(self, *args)
            except ssl.SSLError, err:
                self.clear_hdlers()
                if err.args[0] == ssl.SSL_ERROR_WANT_READ:
                    print "RESCHEDULE - READ"
                    self._read_hdler = event.read(self.ssl_sock, wrapped_func, self, *args)
                elif err.args[0] == ssl.SSL_ERROR_WANT_WRITE:
                    print "RESCHEDULE - WRITE"
                    self._write_hdler = event.write(self.ssl_sock, wrapped_func, self, *args)
                else:
                    self.close()
                    raise
        return handler(wrapped_func)

    def clear_hdlers(self):
        if self._read_hdler:
            self._read_hdler.delete()
            self._read_hdler = None
        if self._write_hdler:
            self._write_hdler.delete()
            self._write_hdler = None

    def __init__(self, ssl_sock, recv_buf, send_buf):
        self.invert = False
        self.ssl_sock = ssl_sock
        self.recv_buf = recv_buf
        self.send_buf = send_buf
        self.other = None
        self._read_hdler = None
        self._write_hdler = None

    def set_ssl_sock(self, ssl_sock):
        self.ssl_sock = ssl_sock

    def start(self, start_read=True):
        print self, "START", start_read, self.ssl_sock
        if start_read:
            self._read_hdler = event.read(self.ssl_sock, self.handshake)
        else:
            print "START WRITE"
            self._write_hdler = event.write(self.ssl_sock, self.handshake)
            print "STARTED WRITE"

    def set_other(self, other):
        self.other = other

    @ssl_handler
    def handshake(self):
        print "DOING HANDSHAKE ON ", self
        self.ssl_sock.do_handshake()
        print "HANDSHAKE DONE"
        self.reschedule()

    @ssl_handler
    def read_data(self):
        in_data = self.ssl_sock.read(1024)
        print "GOT:", in_data
        if (len(in_data) == 0):
            self.close()
        self.recv_buf.buf = self.recv_buf.buf + in_data
        self.reschedule()
        self.other.reschedule()

    @ssl_handler
    def write_data(self):
        len = self.ssl_sock.write(self.send_buf.buf)
        print "SENT:", self.send_buf.buf[:len]
        self.send_buf.buf = self.send_buf.buf[len:]
        self.reschedule()

    def reschedule(self):
        if (self.ssl_sock == None):
            return
        self.clear_hdlers()
        if len(self.send_buf.buf) > 0:
            self._write_hdler = event.write(self.ssl_sock, self.write_data)
        if len(self.recv_buf.buf) < recvbuf_max:
            self._read_hdler = event.read(self.ssl_sock, self.read_data)

    def close(self):
        self.clear_hdlers()
        self.ssl_sock.close()
    

class ProxyConnection:
    def __init__(self, accept_pair):
        in_buf = Buffer("")
        out_buf = Buffer("")

        (in_sock, src) = accept_pair
        in_sock.setblocking(0)
        in_ssl = ssl.wrap_socket(in_sock,
                                 ssl_version = ssl.PROTOCOL_SSLv23,
                                 certfile = certfile,
                                 keyfile = keyfile,
                                 ca_certs = cafile,
                                 server_side = True,
                                 do_handshake_on_connect = False)
        self.in_sstate = ProxyHalf(in_ssl, in_buf, out_buf)
        self.out_sstate = ProxyHalf(None, out_buf, in_buf)
        self.in_sstate.set_other(self.out_sstate)
        self.out_sstate.set_other(self.in_sstate)
        self.in_sstate.start(True)

        out_sock = socket.socket()
        out_sock.setblocking(0)
        # dirty - use connect_ex instead?
        try:
            out_sock.connect((dest_host, dest_port))
        except IOError, e:
            if e.errno != errno.EINPROGRESS:
                raise

        event.write(out_sock, self.connected, out_sock)

    @handler
    def connected(self, out_sock):
        print "CONNECTED"
        out_ssl = ssl.wrap_socket(out_sock,
                                  ssl_version = ssl.PROTOCOL_SSLv23,
                                  do_handshake_on_connect = False)
        self.out_sstate.set_ssl_sock(out_ssl)
        print "START"
        self.out_sstate.start(False)

connections = []

def main(argv):
    # initialize libevent
    event.init()

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

if __name__ == '__main__':
    import sys
    main(sys.argv)
