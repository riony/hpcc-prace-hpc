"""T88 example: the system Python 3.9 (module python/3.9). Prints the array index when given one."""
import platform
import socket
import sys

task = sys.argv[1] if len(sys.argv) > 1 else "-"
print(f"python ok: {platform.python_version()} on {socket.gethostname()}, task {task}")
