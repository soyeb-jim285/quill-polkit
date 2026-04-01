#!/usr/bin/env python3
"""Quill Polkit Authentication Agent.

Registers with PolicyKit as an authentication agent, shows a Quickshell
QML overlay for password input, and authenticates via PolkitAgent.Session.
"""

import json
import os
import signal
import socket
import subprocess
import sys
import threading

import gi

gi.require_version("Gio", "2.0")
gi.require_version("GLib", "2.0")
gi.require_version("Polkit", "1.0")
gi.require_version("PolkitAgent", "1.0")

from gi.repository import Gio, GLib, Polkit, PolkitAgent

SOCKET_PATH = f"/run/user/{os.getuid()}/quill-polkit.sock"
MAX_ATTEMPTS = 3


class QuillPolkitAgent(PolkitAgent.Listener):
    """Polkit authentication agent that delegates UI to Quickshell."""

    def __init__(self):
        super().__init__()
        self._pending = {}  # cookie -> {task, identity, attempts}
        self._sock_server = None
        self._start_socket_server()

    def _start_socket_server(self):
        """Start Unix domain socket server in a background thread."""
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)

        self._sock_server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock_server.bind(SOCKET_PATH)
        os.chmod(SOCKET_PATH, 0o600)
        self._sock_server.listen(5)

        self._sock_thread = threading.Thread(target=self._socket_loop, daemon=True)
        self._sock_thread.start()

    def _socket_loop(self):
        """Accept connections in a background thread, dispatch to GLib main loop."""
        while True:
            try:
                conn, _ = self._sock_server.accept()
                data = conn.recv(4096).decode("utf-8").strip()
                conn.close()
                if data:
                    GLib.idle_add(self._process_message, data)
            except OSError:
                break
            except Exception as e:
                print(f"Socket error: {e}", file=sys.stderr, flush=True)

    def _process_message(self, data):
        """Process a message on the GLib main thread."""
        try:
            msg = json.loads(data)
            cookie = msg.get("cookie", "")
            print(f"Socket received: type={msg.get('type')} cookie={cookie[:20]}...", file=sys.stderr, flush=True)
            if msg.get("type") == "cancel":
                self._handle_cancel(cookie)
            elif msg.get("type") == "password":
                self._handle_password(cookie, msg.get("password", ""))
        except Exception as e:
            print(f"Message error: {e}", file=sys.stderr, flush=True)
        return False  # Don't repeat

    def _ipc(self, function, data):
        """Send IPC message to Quickshell QML."""
        cmd = ["quickshell", "ipc", "call", "polkit", function, json.dumps(data)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                print(f"IPC failed ({result.returncode}): {result.stderr.strip()}", file=sys.stderr, flush=True)
            else:
                print(f"IPC OK: polkit.{function}", file=sys.stderr, flush=True)
        except FileNotFoundError:
            print(f"IPC error: quickshell not found in PATH", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"IPC error: {e}", file=sys.stderr, flush=True)

    def do_initiate_authentication(
        self,
        action_id,
        message,
        icon_name,
        details,
        cookie,
        identities,
        cancellable,
        callback,
        user_data,
    ):
        """Called by polkit when authentication is needed."""
        print(f"AUTH REQUEST: action={action_id} cookie={cookie} message={message}", file=sys.stderr, flush=True)
        task = Gio.Task.new(self, cancellable, callback, user_data)

        # Pick the first unix-user identity
        identity = None
        user_name = "user"
        for ident in identities:
            if isinstance(ident, Polkit.UnixUser):
                identity = ident
                import pwd

                try:
                    user_name = pwd.getpwuid(ident.get_uid()).pw_name
                except KeyError:
                    user_name = str(ident.get_uid())
                break

        if identity is None and identities:
            identity = identities[0]
            user_name = identity.to_string()

        self._pending[cookie] = {
            "task": task,
            "identity": identity,
            "attempts": 0,
            "action_id": action_id,
            "message": message,
            "user_name": user_name,
        }

        self._ipc(
            "beginAuth",
            {
                "cookie": cookie,
                "message": message,
                "user": user_name,
                "actionId": action_id,
            },
        )

    def do_initiate_authentication_finish(self, result):
        """Called by polkit to get the result of authentication."""
        return Gio.Task.is_valid(result, self) and result.propagate_boolean()

    def _handle_password(self, cookie, password):
        """Process password submission from QML."""
        pending = self._pending.get(cookie)
        if not pending:
            return

        pending["attempts"] += 1
        session = PolkitAgent.Session.new(pending["identity"], cookie)

        def on_request(session, request, echo_on):
            session.response(password)

        def on_completed(session, gained_authorization):
            if gained_authorization:
                self._ipc("authSuccess", {"cookie": cookie})
                task = self._pending.pop(cookie, {}).get("task")
                if task:
                    task.return_boolean(True)
            elif pending["attempts"] >= MAX_ATTEMPTS:
                self._ipc(
                    "authFailed",
                    {"cookie": cookie, "message": "Max attempts reached.", "fatal": True},
                )
                task = self._pending.pop(cookie, {}).get("task")
                if task:
                    task.return_boolean(False)
            else:
                remaining = MAX_ATTEMPTS - pending["attempts"]
                self._ipc(
                    "authFailed",
                    {
                        "cookie": cookie,
                        "message": f"Wrong password. {remaining} attempt{'s' if remaining != 1 else ''} remaining.",
                        "fatal": False,
                    },
                )

        def on_show_error(session, text):
            print(f"Polkit session error: {text}", file=sys.stderr)

        session.connect("request", on_request)
        session.connect("completed", on_completed)
        session.connect("show-error", on_show_error)
        session.initiate()

    def _handle_cancel(self, cookie):
        """Handle user cancellation from QML."""
        task = self._pending.pop(cookie, {}).get("task")
        if task:
            task.return_boolean(False)

    def cleanup(self):
        """Clean up socket on exit."""
        if self._sock_server:
            self._sock_server.close()
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)


def get_session_subject():
    """Get the current session subject for agent registration."""
    pid = os.getpid()
    try:
        return Polkit.UnixSession.new_for_process_sync(pid, None)
    except Exception:
        return Polkit.UnixProcess.new_for_owner(pid, 0, os.getuid())


def main():
    agent = QuillPolkitAgent()
    subject = get_session_subject()

    try:
        agent.register(
            PolkitAgent.RegisterFlags.NONE,
            subject,
            "/org/quill/PolkitAgent",
            None,  # cancellable
        )
        print("Quill polkit agent registered.", file=sys.stderr)
    except Exception as e:
        print(f"Failed to register agent: {e}", file=sys.stderr)
        sys.exit(1)

    loop = GLib.MainLoop()

    def shutdown(signum, frame):
        agent.cleanup()
        loop.quit()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    try:
        loop.run()
    finally:
        agent.cleanup()


if __name__ == "__main__":
    main()
