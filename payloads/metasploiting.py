from pymetasploit3.msfrpc import MsfRpcClient
import asyncio 

#we need to get it from .env
from dotenv import load_dotenv
import os
#[ ]TODO: finish out the Metasploit client with a solid schema to align with the mcp server tool registry. Focus on payload delivery and auxililary module integration.
load_dotenv()
class MetasploitClient:
    
    def __init__(self):
        self.MSF_USER = os.getenv("MSF_USER")
        self.MSF_PASS = os.getenv("MSF_PASS")
        self.MSF_HOST = os.getenv("MSF_HOST", "127.0.0.1")
        self.MSF_PORT = int(os.getenv("MSF_PORT", 55553))

        self.client = MsfRpcClient(self.MSF_PASS, user=self.MSF_USER, server=self.MSF_HOST, port=self.MSF_PORT) #thankies

# Functions to interact with Metasploit modules

    def search_module(self, module_name):
        return self.client.modules.search(module_name)

    def use_module(self, module_type, module_name):
        return self.client.modules.use(module_type, module_name)

    def execute_module(self, module_type, module_name):
        return self.client.modules.execute(module_type, module_name)


    def get_module_options(self, module):
        return module.options.items()

    def set_module_option(self, module, option_name, option_value):
        module[option_name] = option_value
        return module[option_name]

    def get_module_option(self, module, option_name):
        return module[option_name]

    def get_payloads(self):
        return self.client.modules.payloads.items()

    def load_payload(self, payload_name):
        return self.client.modules.payloads[payload_name]

    def get_exploits(self):
        return self.client.modules.exploits.items()

    def use_exploit(self, exploit_name):
        return self.client.modules.exploits[exploit_name]

    def get_auxiliary(self):
        return self.client.modules.auxiliary.items()

    def load_auxiliary(self, auxiliary_name):
        return self.client.modules.auxiliary[auxiliary_name]

    def get_post(self):
        return self.client.modules.post.items() #thanks

    def load_post(self, post_name):
        return self.client.modules.post[post_name]


    def get_encoders(self):
        return self.client.modules.encoders.items()

    def load_encoder(self, encoder_name):
        return self.client.modules.encoders[encoder_name]

    def get_nops(self):
        return self.client.modules.nops.items() #nop modules are used to generate no-operation instructions

    def load_nop(self, nop_name):
        return self.client.modules.nops[nop_name]

    def get_auxiliary_post(self): #the difference between this and get_auxiliary is?
        return list(self.client.modules.auxiliary.items()) + list(self.client.modules.post.items()) #combines auxiliary and post modules fair

    def load_auxiliary_post(self, module_name):
        if module_name in self.client.modules.auxiliary:
            return self.client.modules.auxiliary[module_name]
        elif module_name in self.client.modules.post:
            return self.client.modules.post[module_name]
        else:
            return None





