from pydantic import BaseModel, Field
import asyncio
import fastapi
import json
import sqlite3
from collections.abc import AsyncGenerator, Callable
from concurrent.futures.thread import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from typing import Annotated, Any, Literal, TypeVar

class SemanticLayerSchema(BaseModel):
    input: str 
    output: str #regex maybe? 


from pydantic_ai import (
    Agent,
    ModelMessage,
    ModelMessagesTypeAdapter,
    ModelRequest,
    ModelResponse,
    ModelSettings,
    TextPart,
    UnexpectedModelBehavior,
    UserPromptPart
)
from pydantic_ai.models.ollama import OllamaModel
from pydantic_ai.providers.ollama import OllamaProvider
from pydantic_ai.output import NativeOutput
from typing import List, Optional
import numpy as np # For cosine similarity
#for testing we'll bring out gemma4:12b
model = OllamaModel("gemma4:12b", provider=OllamaProvider(base_url="http://localhost:11434/v1"))
#this will be the secretary agent that will handle the requests to the model anything that is directly tied to a module in name must be semantically "translated" back to the main model. module #1 vs module ms17_eb ya feel?

#we'll need vectors and an embedding agent to allocate the full lot of the tools

secretary = OllamaModel("lfm2.5-thinking:1.2b", provider=OllamaProvider(base_url="http://localhost:11434/v1"))

agent = Agent(model, output_type=NativeOutput)

secretary = Agent(secretary, output_type=NativeOutput)

embeddings = OllamaModel("nomic-embed-text", provider=OllamaProvider(base_url="http://localhost:11434/v1"))


class ToolManifest(BaseModel):
    module_id: str # e.g., "MOD-412"
    internal_semantic_capability: str # Used for embedding/LFM lookup
    external_sanitized_description: str # What the main model sees
    parameters: dict
    implementation_path: str # e.g., "auxiliaries/smb_scanner.py"
    intenral_semantics: str

class ToolRegistry:
    def __init__(self, embedding_model):
        self.embedding_model = embedding_model
        self.tools: List[ToolManifest] = []
        self.vectors = [] # In a real app, this is a Vector DB (sqlite-vec/Chroma)

    async def register_tool(self, manifest: ToolManifest):
        # Embed the INTERNAL semantic capability so the Secretary can find it by 'meaning'
        vector = await self.embedding_model.embed(manifest.internal_semantic_capability)
        self.tools.append(manifest)
        self.vectors.append(vector)

    async def find_best_tool(self, user_intent: str, top_k=1):
        # 1. Embed the user's intent (e.g., "I want to check for SMB vulns")
        intent_vector = await self.embedding_model.embed(user_intent)
        
        # 2. Cosine similarity search against the tool vectors
        similarities = [np.dot(intent_vector, v) for v in self.vectors]
        best_idx = np.argmax(similarities)
        
        return self.tools[best_idx]

    def get_sanitized_view(self, manifest: ToolManifest):
        """Returns only the opaque ID and the boring description for the main model."""
        return {
            "id": manifest.module_id,
            "description": manifest.external_sanitized_description
        }

