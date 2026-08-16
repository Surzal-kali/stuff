import subprocess
import sys
import asyncio
from pathlib import Path


listener = Path(__file__).parent / "plugins" / "listen.cpp"

def compile_tcp():
    if not listener.exists():
        print(f"[!] Listener source not found at {listener}")
        return

    output_binary = listener.with_suffix('')
    try:
        subprocess.run(["g++", str(listener), "-o", str(output_binary)], check=True)
        print(f"[+] Successfully compiled {listener} to {output_binary}")
    except subprocess.CalledProcessError as e:
        print(f"[-] Compilation failed: {e}")


def execute_tcp(ip="127.0.0.1", port=4444):
    binary_path = listener.with_suffix('')
    if not binary_path.exists():
        print(f"[!] Listener binary not found at {binary_path}. Please compile it first.")
        return
    try:
        subprocess.run([str(binary_path), ip, str(port)], check=True)
        print(f"[+] Successfully executed {binary_path} with IP: {ip} and Port: {port}")
    except subprocess.CalledProcessError as e:
        print(f"[-] Execution failed: {e}")