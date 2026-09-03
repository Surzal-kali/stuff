import os
import requests
import json
from datetime import datetime
from pydantic import BaseModel, Field
from typing import Any, Dict, Optional

class Tools:
    def __init__(self):
        # Load API key from environment to avoid hardcoding
        self.framework_api_key = os.getenv("Surzal4824!$")
        self.framework_url = os.getenv("FRAMEWORK_URL", "http://localhost:7000")

    def framework_execute(
        self,
        intent: str = Field(
            ..., 
            description="The semantic intent of the security operation. Be descriptive (e.g., 'Run an SMB scan on 192.168.1.1' or 'Inject payload into session 123')."
        ),
        arguments: Optional[Dict[str, Any]] = Field(
            default=None, 
            description="Additional keyword arguments required by the tool (e.g., {'targets': ['192.168.1.1'], 'port': 445})."
        ),
    ) -> str:
        """
        Execute a tool from the Modular Security Framework. 
        This tool uses a vector database to semantically match your intent to the best available security module.
        """
        if not self.framework_api_key:
            return "Error: FRAMEWORK_API_KEY not set in environment variables."

        endpoint = f"{self.framework_url}/tools/execute"
        headers = {
            "X-API-Key": self.framework_api_key,
            "Content-Type": "application/json"
        }
        payload = {
            "intent": intent,
            "arguments": arguments or {}
        }

        try:
            response = requests.post(endpoint, json=payload, headers=headers, timeout=60)
            response.raise_for_status()
            data = response.json()
            
            # Extract tool identity and result from the enriched API response
            tool_id = data.get("tool_id", "Unknown ID")
            tool_name = data.get("tool_name", "Unknown Tool")
            result = data.get("result", "No result returned")
            
            formatted_response = {
                "activated_tool": f"{tool_name} ({tool_id})",
                "execution_result": result
            }
            
            return json.dumps(formatted_response, indent=2)
        except requests.exceptions.RequestException as e:
            return f"Framework Execution Error: {str(e)}"
    def framework_search_memory(
        self,
        namespace: str = Field(
            ..., 
            description="The memory namespace to search (e.g., 'intel', 'sessions', 'targets')."
        ),
        query_text: str = Field(
            ..., 
            description="The text keyword or phrase to search for within the memory vault."
        ),
    ) -> str:
        """
        Search the framework's long-term memory store using text-based keyword matching.
        Use this to retrieve stored intelligence, session data, or previous findings.
        """
        endpoint = f"{self.framework_url}/memory/search"
        headers = {"X-API-Key": self.framework_api_key, "Content-Type": "application/json"}
        payload = {
            "namespace": namespace,
            "query_text": query_text
        }

        try:
            response = requests.post(endpoint, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            return json.dumps(response.json(), indent=2)
        except requests.exceptions.RequestException as e:
            return f"Memory Search Error: {str(e)}"

    def framework_recall_memory(
        self,
        namespace: str = Field(
            ..., 
            description="The memory namespace to recall from."
        ),
        query_embedding: list = Field(
            ..., 
            description="The embedding vector for semantic similarity search. (Note: This must be a list of floats)."
        ),
        limit: int = Field(
            5, 
            description="Maximum number of results to return."
        ),
    ) -> str:
        """
        Perform a semantic recall from the framework's memory vault using a vector embedding.
        This is used for high-precision similarity matching.
        """
        endpoint = f"{self.framework_url}/memory/recall"
        headers = {"X-API-Key": self.framework_api_key, "Content-Type": "application/json"}
        payload = {
            "namespace": namespace,
            "query_embedding": query_embedding,
            "limit": limit
        }

        try:
            response = requests.post(endpoint, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            return json.dumps(response.json(), indent=2)
        except requests.exceptions.RequestException as e:
            return f"Memory Recall Error: {str(e)}"