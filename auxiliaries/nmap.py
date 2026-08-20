import subprocess


class Nmap:
    def __init__(self, target):
        self.target = target

    def scan(self, options=""):
        command = f"nmap {options} {self.target}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout