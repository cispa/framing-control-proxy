import subprocess
import traceback
import signal
import select
import socket
import time
import os


class ProxyDefinition:
    SERVER_PORT = None
    IN_PORT = 0
    IN_SOCKET = None

    def __init__(self, port):
        self.SERVER_PORT = port


class ProxyContainer:
    by_in_port = dict()
    by_socket = dict()


class InterceptorV4:
    TIMEOUT = 30
    BUFFER_SIZE = 2 ** 16

    DEFAULT_LB = "127.0.0.1"
    WHITELISTED_LB = "127.0.0.2"
    TARGET_IP = "0.0.0.0"

    proxies = ProxyContainer

    should_fork = True
    is_child = False

    revert = []

    def __init__(self, proxy_func, verbose=False, debug=False):
        self.proxy_function = proxy_func
        self.verbose = verbose
        self.debug = debug

    def print(self, *argv):
        if self.verbose:
            print(*argv)

    def shutdown(self):
        for cmd in self.revert:
            d = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
            self.print("Revert:", d)

    def redirect_port(self, proxy_def):

        setup_output = ['iptables', '-t', 'nat', '-I', 'OUTPUT', '!', '--src', self.WHITELISTED_LB,
                        '-p', 'tcp', '--dport',
                        str(proxy_def.SERVER_PORT), '-j', 'REDIRECT', '--to-ports',
                        str(proxy_def.IN_PORT), '-w', '5', '-m', 'comment', '--comment',
                        'SWAGSecurityProxy ({}:{})'.format(self.TARGET_IP, proxy_def.SERVER_PORT)]

        setup_pre = setup_output[:4] + ["PREROUTING"] + setup_output[5:]

        self.revert.append(setup_output[:3] + ["-D"] + setup_output[4:])
        self.revert.append(setup_pre[:3] + ["-D"] + setup_pre[4:])
        self.print('IP Tables Pre', setup_pre)
        pre = subprocess.Popen(setup_pre, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        self.print("Pre Setup (ipv4):", pre)
        self.print('IP Tables Out', setup_output)
        out = subprocess.Popen(setup_output, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        self.print("Out Setup (ipv4):", out)

    def new_proxy(self, in_port):

        proxy_def = ProxyDefinition(in_port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.TARGET_IP, proxy_def.IN_PORT))
        except Exception as e:
            self.print('Socket binding for IN_PORT failed', e)
            exit()
        proxy_def.IN_SOCKET = s
        proxy_def.IN_PORT = s.getsockname()[1]
        self.proxies.by_in_port[proxy_def.IN_PORT] = proxy_def
        self.proxies.by_socket[s] = proxy_def
        s.setblocking(False)
        s.listen(5)
        self.redirect_port(proxy_def)

    send_buffer = dict()

    def send(self, s, data):
        if s not in self.send_buffer:
            self.send_buffer[s] = data
        else:
            self.send_buffer[s] += data

    def open_local_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        sock.bind((self.WHITELISTED_LB, 0))
        return sock

    def run(self):
        idle = False
        connections_by_server = {}
        connections_by_clients = {}
        self.send_buffer = {}
        last_log = time.time()

        def drop_client_connection(cc):
            if self.debug:
                self.print("Connection closed:", cc.getsockname())
            try:
                conns = connections_by_clients[cc] if cc in connections_by_clients else connections_by_server[cc]
                _, client, server = conns
            except:
                return
            try:
                client.close()
            except:
                pass
            try:
                server.close()
            except:
                pass
            try:
                del connections_by_clients[client]
            except:
                pass
            try:
                del connections_by_server[server]
            except:
                pass
            try:
                del self.send_buffer[client]
            except:
                pass
            try:
                del self.send_buffer[server]
            except:
                pass

        while True:

            if idle:
                time.sleep(0.02)  # CPU needs sleep :)
            idle = True

            try:
                if not self.should_fork:
                    ins = list(map(lambda x: x.IN_SOCKET, self.proxies.by_in_port.values()))
                    ins += list(connections_by_clients.keys()) + list(connections_by_server.keys())
                elif self.is_child:
                    ins = list(connections_by_clients.keys()) + list(connections_by_server.keys())
                else:
                    ins = list(map(lambda x: x.IN_SOCKET, self.proxies.by_in_port.values()))

                if not ins:
                    if not self.is_child:
                        self.print("main process has no active sockets :(")
                        exit(1)
                    elif self.debug:
                        self.print("child terminated")
                    exit(0)

                if self.debug and not self.is_child and time.time() - last_log > 5:
                    self.print("-------- LISTENERS -----------")
                    self.print(list(map(lambda x: x.IN_SOCKET.getsockname(), self.proxies.by_in_port.values())))
                    last_log = time.time()

                readable_socket, writable_socket, error_socket = select.select(ins, ins, ins, 0.2)

                for s in readable_socket:
                    if not self.is_child and s in self.proxies.by_socket:
                        idle = False
                        # s is IN_SOCKET
                        dst = self.proxies.by_socket[s]
                        client_socket, adr = s.accept()
                        if self.should_fork:
                            child_id = os.fork()
                            self.is_child = child_id == 0
                            if not self.is_child:
                                client_socket.close()
                                if self.debug:
                                    self.print("forked:", child_id)
                                continue
                            else:
                                signal.alarm(self.TIMEOUT)

                                def alarm_handler(signal_number, stack_frame):
                                    self.print('Got Alarm:', signal_number, stack_frame)
                                    for i in list(connections_by_clients.keys()):
                                        i.close()
                                        del connections_by_clients[i]
                                    for i in list(connections_by_server.keys()):
                                        i.close()
                                        del connections_by_server[i]
                                    time.sleep(0.2)
                                    exit(0)

                                signal.signal(signal.SIGALRM, alarm_handler)
                                self.send_buffer = dict()
                                self.proxies.by_in_port = dict()
                                self.revert = []
                        self.print("New incoming connection: ", adr, " -> :", dst.IN_PORT,
                                   " ( :", dst.SERVER_PORT, " )")
                        client_socket.setblocking(False)
                        send_socket = self.open_local_socket()
                        connections_by_clients[client_socket] = (dst, client_socket, send_socket)
                        connections_by_server[send_socket] = (dst, client_socket, send_socket)
                        try:
                            send_socket.connect((self.DEFAULT_LB, dst.SERVER_PORT))
                            if self.debug:
                                self.print("connection established: ", adr, "-> :",
                                           dst.IN_PORT, " -> :", dst.SERVER_PORT)
                        except:
                            s = "Exception while trying to connect to {}:{}"
                            self.print(s.format(self.DEFAULT_LB, str(dst.SERVER_PORT)))
                            drop_client_connection(client_socket)

                    elif (not self.should_fork or self.is_child) and s in connections_by_clients.keys():
                        idle = False
                        try:
                            msg = s.recv(self.BUFFER_SIZE)
                        except:
                            msg = ""
                        if msg != "":
                            dst, s_cli, s_srv = connections_by_clients[s]
                            data = self.proxy_function(msg, s_cli, True)
                            self.send(s_srv, data)
                        else:
                            drop_client_connection(s)
                    elif (not self.should_fork or self.is_child) and s in connections_by_server.keys():
                        idle = False
                        try:
                            msg = s.recv(self.BUFFER_SIZE)
                        except:
                            msg = ""
                        if msg != "":
                            dst, s_cli, s_srv = connections_by_server[s]
                            data = self.proxy_function(msg, s_cli, False)
                            self.send(s_cli, data)
                        else:
                            drop_client_connection(s)
                    else:
                        self.print("Unknown Socket:", s)
                for s in list(self.send_buffer.keys()):
                    if s not in self.send_buffer:
                        continue
                    data = self.send_buffer[s]
                    if data == "":
                        del self.send_buffer[s]
                    elif s in writable_socket:
                        idle = False
                        sent = s.send(data)
                        if sent == 0:
                            drop_client_connection(s)
                        elif sent != len(data):
                            self.send_buffer[s] = data[sent:]
                        else:
                            del self.send_buffer[s]
                for s in error_socket:
                    idle = False
                    self.print("Error :(")
                    drop_client_connection(s)

            except socket.timeout:
                self.print('Socket Timeout Occurred')
                continue

            except select.error:
                self.print("Select Error")
                traceback.print_exc()
                break

            except socket.error:
                self.print("Socket Error")
                traceback.print_exc()
                break


class InterceptorV6(InterceptorV4):
    DEFAULT_LB = "::1"
    WHITELISTED_LB = "fe80::1/64"
    TARGET_IP = "::"

    def __init__(self, proxy_func, verbose=False, debug=False):
        InterceptorV4.__init__(self, proxy_func, verbose, debug)

    def open_local_socket(self):
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
        address = None
        for address_info in socket.getaddrinfo(self.WHITELISTED_LB.split("/")[0] + "%lo", 0):
            if address_info[0] == socket.AF_INET6 and address_info[1] == socket.SOCK_STREAM:
                address = address_info[4]
                break
        assert address is not None
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.bind(address)
        return s

    def redirect_port(self, proxy_def):

        loop_back = ["ip", "-6", "address", "add", self.WHITELISTED_LB, "dev", "lo"]
        self.print(loop_back)

        data = subprocess.Popen(loop_back, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        self.print("Loopback Setup (ipv6):", data)

        setup_output = ['ip6tables', '-t', 'nat', '-I', 'OUTPUT', '!', '--src', self.WHITELISTED_LB,
                        '-p', 'tcp', '--dport',
                        str(proxy_def.SERVER_PORT), '-j', 'REDIRECT', '--to-ports',
                        str(proxy_def.IN_PORT), '-w', '5', '-m', 'comment', '--comment',
                        'SWAGSecurityProxy ([{}]:{})'.format(self.TARGET_IP, proxy_def.SERVER_PORT)]

        setup_pre = setup_output[:4] + ["PREROUTING"] + setup_output[5:]
        self.revert.append(setup_output[:3] + ["-D"] + setup_output[4:])
        self.revert.append(setup_pre[:3] + ["-D"] + setup_pre[4:])
        self.print(setup_pre)

        data = subprocess.Popen(setup_pre, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        self.print("Pre Setup (ipv6):", data)
        self.print(setup_output)
        data = subprocess.Popen(setup_output, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        self.print("Output Setup (ipv6):", data)

    def new_proxy(self, proxy_def):
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.TARGET_IP, proxy_def.IN_PORT))
        except Exception as e:
            self.print(e)
            self.print("Socket binding for IN_PORT failed")
            exit()
            proxy_def.IN_SOCKET = s
            proxy_def.IN_PORT = s.getsockname()[1]
            self.proxies.by_in_port[proxy_def.IN_PORT] = proxy_def
            self.proxies.by_socket[s] = proxy_def
            s.setblocking(False)
            s.listen(5)
            self.redirect_port(proxy_def)
