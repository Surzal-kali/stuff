import shlex
import subprocess

from constants import framework_tool


class Nmap:
    def __init__(self, target):
        self.target = target

    def scan(self, options="-Pn -sV"):
        # shlex splits the option string into argv elements; the target is its
        # own element, so shell metacharacters in it are passed through to nmap
        # verbatim instead of being interpreted by a shell.
        command = ["nmap", *shlex.split(options), self.target]
        # Bounded so a wedged scan can't hang a dispatch worker forever; the
        # harness side has its own BRAIN_DISPATCH_TIMEOUT as a second net.
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        return result.stdout or result.stderr


@framework_tool("Run an Nmap scan on a target with specified options.")
def run_nmap(target, options="-Pn -sV"):
    # -Pn by default: hosts that drop ping probes would otherwise report
    # "Host seems down" even when their ports are reachable.
    #
    # Deliberately synchronous: both dispatchers run sync tools in a worker
    # thread (run_in_executor / asyncio.to_thread). Keeping it async would pin
    # the blocking subprocess call to the event loop and freeze the harness
    # for the whole scan.
    nmap = Nmap(target)
    return nmap.scan(options)