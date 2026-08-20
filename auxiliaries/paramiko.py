import paramiko
import os
import sys
from dotenv import load_dotenv
import asyncio

load_dotenv()
#[ ]TODO: finish out the paramiko client with a solid schema to align with the mcp server tool registry
class ParamikoClient:
    async def __init__(self, host, username, password=None):
        self.host = host
        self.username = username
        self.password = password
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(host, username=username, password=password)

    async def execute(self, payload):
        if payload:
            stdin, stdout, stderr = self.client.exec_command(payload)
            return stdout.read().decode(), stderr.read().decode()
        return None, None
    def close(self):
        self.client.close()


