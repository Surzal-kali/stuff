import subprocess


class Nmap:
    def __init__(self, target):
        self.target = target

    def scan(self, options=""):
        command = f"nmap {options} {self.target}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout


async def run_nmap(target, options=""):
    nmap = Nmap(target)
    return nmap.scan(options)