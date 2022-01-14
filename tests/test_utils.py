import socket
import threading
import os
import time

# oneshot UNIX to TCP socket proxy. Stops after first connection
def unix2tcp(unix_socket_path, tcp_host, tcp_port):
    try:
        os.unlink(unix_socket_path)
    except OSError:
        pass

    usock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    tsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    usock.bind(unix_socket_path)
    usock.listen(1)

    def proxy_loop():
        uconn, addr = usock.accept()
        tsock.connect((tcp_host, tcp_port))

        uconn.setblocking(False)
        tsock.setblocking(False)

        while True:
            data = None

            try:
                data = uconn.recv(1000)
                if len(data) == 0:
                    break
                tsock.sendall(data)
            except BlockingIOError: 
                pass

            try:
                data = tsock.recv(1000)
                if len(data) == 0:
                    break
                uconn.sendall(data)
            except BlockingIOError: 
                pass

        usock.close()
        uconn.close()
        tsock.close()

    threading.Thread(target=proxy_loop, daemon=True).start()

