"""Bind the HTTP handler to an operator-owned Unix socket for SSH forwarding."""

import os
import socket
import stat
from contextlib import contextmanager
from socketserver import TCPServer


@contextmanager
def open_private_socket(server_class, socket_path, port, handler, *, proxy_gid=None):
    if not hasattr(socket, "AF_UNIX") or not hasattr(os, "geteuid"):
        raise ValueError("Unix-Sockets werden auf diesem System nicht unterstützt.")
    if not socket_path.is_absolute() or not 1 <= port <= 65535:
        raise ValueError("Ein Unix-Socket braucht einen absoluten Pfad und einen festen Browser-Port.")
    directory = socket_path.parent.lstat()
    directory_mode = 0o700 if proxy_gid is None else 0o710
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid()
            or stat.S_IMODE(directory.st_mode) != directory_mode
            or proxy_gid is not None and directory.st_gid != proxy_gid):
        raise ValueError(f"Das Socket-Verzeichnis braucht den Dienstnutzer, Modus {directory_mode:04o} und die konfigurierte Gruppe.")

    class UnixHTTPServer(server_class):
        address_family = socket.AF_UNIX
        allow_reuse_address = False

        def server_bind(self):
            # HTTPServer's override assumes a TCP host/port tuple.
            TCPServer.server_bind(self)
            self.server_name = "localhost"
            self.server_port = port

    with UnixHTTPServer(os.fspath(socket_path), handler, bind_and_activate=False) as server:
        server.server_bind()
        identity = socket_path.lstat()
        try:
            if proxy_gid is not None:
                os.chown(socket_path, -1, proxy_gid)
            socket_path.chmod(0o600 if proxy_gid is None else 0o660)
            server.server_activate()
            yield server
        finally:
            # Do not remove a socket that another process substituted at the path.
            try:
                current = socket_path.lstat()
                if os.path.samestat(identity, current):
                    socket_path.unlink()
            except FileNotFoundError:
                pass
