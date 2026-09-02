import subprocess

import asyncio 
import os
#[ ]TODO: integrate the metasploit framework mcp through subprocess calls and regex extraction. 

async def summon_msf_console():
    """
    This function summons the Metasploit console using subprocess.
    It runs the 'msfconsole' command and captures its output.
    """
    try:
        # Start the Metasploit console
        process = subprocess.Popen(['msfconsole'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Capture the output and error streams
        stdout, stderr = process.communicate()
        
        # Decode the output to a string
        output = stdout.decode('utf-8')
        error = stderr.decode('utf-8')
        
        if process.returncode != 0:
            print(f"Error starting msfconsole: {error}")
            return None
        
        return output
    
    except Exception as e:
        print(f"An error occurred while trying to summon msfconsole: {e}")
        return None

async def load_mcp():
    """
    This function loads the Metasploit Community Platform (MCP) using subprocess.
    It runs the 'msfconsole' command with specific arguments to load MCP.
    """
    try:
        # Start the Metasploit console with MCP
        process = subprocess.Popen(['msfconsole', '-x', 'load mcp'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Capture the output and error streams
        stdout, stderr = process.communicate()
        
        # Decode the output to a string
        output = stdout.decode('utf-8')
        error = stderr.decode('utf-8')
        
        if process.returncode != 0:
            print(f"Error loading MCP: {error}")
            return None
        
        return output
    
    except Exception as e:
        print(f"An error occurred while trying to load MCP: {e}")
        return None

def extract_mcp_info(output):
    """
    This function extracts relevant information from the MCP output using regex.
    It looks for specific patterns in the output to gather useful data.
    """
    import re
    
    # Example regex pattern to extract information (adjust as needed)
    apitoken = r"Bearer\s+([A-Za-z0-9\-_]+)"
    msfpass = r"Pass:\s+([A-Za-z0-9\-_]+)"
    
    matches = re.findall(apitoken, output)
    matches.extend(re.findall(msfpass, output))
    return matches

if __name__ == "__main__":
    # Run the async functions in an event loop
    loop = asyncio.get_event_loop()
    msf_output = loop.run_until_complete(summon_msf_console())
    mcp_output = loop.run_until_complete(load_mcp())
    
    if msf_output:
        print("Metasploit Console Output:")
        print(msf_output)
    
    if mcp_output:
        print("MCP Output:")
        print(mcp_output)
        
        # Extract information from the MCP output
        extracted_info = extract_mcp_info(mcp_output)
        print("Extracted Information:")
        for info in extracted_info:
            print(info)