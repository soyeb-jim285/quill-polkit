#!/usr/bin/env python3
"""Quill Polkit Authentication Agent.

Registers with PolicyKit as an authentication agent via D-Bus,
shows a Quickshell QML overlay for password input, and authenticates
via polkit-agent-helper-1.
"""

import asyncio
import json
import os
import pwd
import signal
import socket
import subprocess
import sys

from dbus_next.aio import MessageBus
from dbus_next.service import ServiceInterface, method
from dbus_next import Variant, BusType

SOCKET_PATH = f"/run/user/{os.getuid()}/quill-polkit.sock"
HELPER_PATH = "/usr/lib/polkit-1/polkit-agent-helper-1"
MAX_ATTEMPTS = 3
OBJECT_PATH = "/org/quill/PolkitAgent"


def ipc(function, data):
    """Send IPC message to Quickshell QML."""
    try:
        subprocess.Popen(
            ["quickshell", "ipc", "call", "polkit", function, json.dumps(data)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        print(f"IPC error: {e}", file=sys.stderr, flush=True)


async def authenticate_with_helper(username, cookie, password):
    """Run polkit-agent-helper-1 to authenticate.

    The helper protocol:
    - Write cookie to stdin
    - Helper sends "PAM_PROMPT_ECHO_OFF <prompt>" to stdout
    - Write password to stdin
    - Helper exits 0 on success, 1 on failure
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            HELPER_PATH, username,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        # Send cookie first, then wait for prompt, then send password
        proc.stdin.write(f"{cookie}\n".encode())
        await proc.stdin.drain()

        # Read the PAM prompt
        line = await asyncio.wait_for(proc.stdout.readline(), timeout=5)
        prompt = line.decode().strip()
        print(f"Helper prompt: {prompt}", file=sys.stderr, flush=True)

        # Send password
        proc.stdin.write(f"{password}\n".encode())
        await proc.stdin.drain()
        proc.stdin.close()

        await asyncio.wait_for(proc.wait(), timeout=10)
        return proc.returncode == 0
    except Exception as e:
        print(f"Helper error: {e}", file=sys.stderr, flush=True)
        return False


class PolkitAgentInterface(ServiceInterface):
    """D-Bus interface for org.freedesktop.PolicyKit1.AuthenticationAgent."""

    def __init__(self):
        super().__init__("org.freedesktop.PolicyKit1.AuthenticationAgent")
        self._pending = {}  # cookie -> dict

    @method()
    async def BeginAuthentication(
        self,
        action_id: "s",
        message: "s",
        icon_name: "s",
        details: "a{ss}",
        cookie: "s",
        identities: "a(sa{sv})",
    ) -> None:
        """Called by polkit when authentication is needed."""
        print(f"AUTH REQUEST: action={action_id} cookie={cookie[:30]}... message={message}", file=sys.stderr, flush=True)

        # Find the unix user identity
        username = "root"
        for kind, ident_details in identities:
            if kind == "unix-user":
                uid = ident_details.get("uid")
                if uid:
                    uid_val = uid.value
                    try:
                        username = pwd.getpwuid(uid_val).pw_name
                    except KeyError:
                        username = str(uid_val)
                break

        # Create a future to wait for auth completion
        future = asyncio.get_event_loop().create_future()
        self._pending[cookie] = {
            "future": future,
            "username": username,
            "attempts": 0,
        }

        # Signal QML to show the dialog
        ipc("beginAuth", {
            "cookie": cookie,
            "message": message,
            "user": username,
            "actionId": action_id,
        })

        # Wait for auth to complete (blocks the D-Bus method return)
        try:
            result = await asyncio.wait_for(future, timeout=120)
            if not result:
                raise Exception("Authentication failed")
        except asyncio.TimeoutError:
            self._pending.pop(cookie, None)
            ipc("cancelAuth", {"cookie": cookie})
            raise Exception("Authentication timed out")
        except Exception:
            self._pending.pop(cookie, None)
            raise

    @method()
    def CancelAuthentication(self, cookie: "s") -> None:
        """Called by polkit to cancel an in-progress authentication."""
        print(f"CANCEL REQUEST: cookie={cookie[:30]}...", file=sys.stderr, flush=True)
        pending = self._pending.pop(cookie, None)
        if pending and not pending["future"].done():
            pending["future"].set_result(False)
        ipc("cancelAuth", {"cookie": cookie})

    async def handle_password(self, cookie, password):
        """Process password submission from QML."""
        pending = self._pending.get(cookie)
        if not pending:
            print(f"No pending request for cookie {cookie[:20]}...", file=sys.stderr, flush=True)
            return

        pending["attempts"] += 1
        username = pending["username"]
        print(f"Authenticating {username} (attempt {pending['attempts']}/{MAX_ATTEMPTS})", file=sys.stderr, flush=True)

        success = await authenticate_with_helper(username, cookie, password)

        if success:
            print(f"Auth SUCCESS for {username}", file=sys.stderr, flush=True)
            ipc("authSuccess", {"cookie": cookie})
            if not pending["future"].done():
                pending["future"].set_result(True)
            self._pending.pop(cookie, None)
        elif pending["attempts"] >= MAX_ATTEMPTS:
            print(f"Auth FAILED - max attempts for {username}", file=sys.stderr, flush=True)
            ipc("authFailed", {
                "cookie": cookie,
                "message": "Max attempts reached.",
                "fatal": True,
            })
            if not pending["future"].done():
                pending["future"].set_result(False)
            self._pending.pop(cookie, None)
        else:
            remaining = MAX_ATTEMPTS - pending["attempts"]
            print(f"Auth FAILED - {remaining} attempts remaining for {username}", file=sys.stderr, flush=True)
            ipc("authFailed", {
                "cookie": cookie,
                "message": f"Wrong password. {remaining} attempt{'s' if remaining != 1 else ''} remaining.",
                "fatal": False,
            })

    def handle_cancel(self, cookie):
        """Handle user cancellation from QML."""
        pending = self._pending.pop(cookie, None)
        if pending and not pending["future"].done():
            pending["future"].set_result(False)


async def register_agent(bus):
    """Register this agent with the polkit authority on the system bus."""
    system_bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    introspection = await system_bus.introspect(
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
    )
    proxy = system_bus.get_proxy_object(
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
        introspection,
    )
    authority = proxy.get_interface("org.freedesktop.PolicyKit1.Authority")

    # Get session ID
    session_id = None
    try:
        result = subprocess.run(
            ["loginctl", "show-session", "auto", "-p", "Id", "--value"],
            capture_output=True, text=True, timeout=5,
        )
        session_id = result.stdout.strip()
    except Exception:
        session_id = "auto"

    if not session_id:
        session_id = "auto"

    # Register as auth agent for this session
    subject = ["unix-session", {"session-id": Variant("s", session_id)}]
    locale = os.environ.get("LANG", "en_US.UTF-8")

    await authority.call_register_authentication_agent(
        subject, locale, OBJECT_PATH,
    )

    print(f"Agent registered for session {session_id} on {bus.unique_name}", file=sys.stderr, flush=True)
    return system_bus


async def socket_server(agent):
    """Unix domain socket server for receiving passwords from QML."""
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0o600)
    server.listen(5)
    server.setblocking(False)

    loop = asyncio.get_event_loop()

    while True:
        conn, _ = await loop.sock_accept(server)
        try:
            data = (await loop.sock_recv(conn, 4096)).decode("utf-8").strip()
            conn.close()
            if data:
                msg = json.loads(data)
                cookie = msg.get("cookie", "")
                msg_type = msg.get("type", "")
                print(f"Socket: type={msg_type} cookie={cookie[:20]}...", file=sys.stderr, flush=True)
                if msg_type == "cancel":
                    agent.handle_cancel(cookie)
                elif msg_type == "password":
                    asyncio.create_task(agent.handle_password(cookie, msg.get("password", "")))
        except Exception as e:
            print(f"Socket error: {e}", file=sys.stderr, flush=True)
            try:
                conn.close()
            except Exception:
                pass


async def main():
    # Connect to session bus and export our agent interface
    bus = await MessageBus().connect()
    agent = PolkitAgentInterface()
    bus.export(OBJECT_PATH, agent)

    # Register with polkit authority
    system_bus = await register_agent(bus)

    # Start socket server
    socket_task = asyncio.create_task(socket_server(agent))

    print("Quill polkit agent running.", file=sys.stderr, flush=True)

    # Wait forever
    stop = asyncio.get_event_loop().create_future()

    def shutdown():
        if not stop.done():
            stop.set_result(True)

    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGTERM, shutdown)
    loop.add_signal_handler(signal.SIGINT, shutdown)

    try:
        await stop
    finally:
        socket_task.cancel()
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)
        system_bus.disconnect()
        bus.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
