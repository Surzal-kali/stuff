from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
from daharness import ToolRegistry, OllamaEmbeddingFunction

class ToolRequest(BaseModel):
    intent: str
    arguments: Optional[dict] = None

class MemorySearchRequest(BaseModel):
    namespace: str
    query_text: Optional[str] = None

class MemoryRecallRequest(BaseModel):
    namespace: str
    query_embedding: list
    limit: Optional[int] = 5

class APIGateway:
    def __init__(self, tool_registry: ToolRegistry, memory_service):
        self.tool_registry = tool_registry
        self.memory_service = memory_service
        self.app = FastAPI()

        @self.app.post("/tools/execute")
        async def execute_tool(req: ToolRequest):
            manifest = await self.tool_registry.find_best_tool(req.intent)
            if not manifest:
                raise HTTPException(404, "No tool found for intent")
            return await self.tool_registry.execute_tool(manifest, req.arguments or {})

        @self.app.post("/memory/search")
        async def search_memory(req: MemorySearchRequest):
            if not req.query_text:
                raise HTTPException(400, "query_text is required for text-based search")
            return self.memory_service.search(
                namespace=req.namespace,
                query_text=req.query_text,
            )

        @self.app.post("/memory/recall")
        async def recall_memory(req: MemoryRecallRequest):
            return self.memory_service.recall(
                namespace=req.namespace,
                query_embedding=req.query_embedding,
                limit=req.limit,
            )

if __name__ == "__main__":
    # Initialize the embedding function
    embedding_function = OllamaEmbeddingFunction(model_name="nomic-embed-text")

    # Initialize ToolRegistry with the embedding function
    tool_registry = ToolRegistry(
        embedding_model=embedding_function,
        mcp_servers={"metasploit": "http://localhost:55552"},
    )

    # Initialize MemoryService
    from memories import MemoryService
    memory_service = MemoryService(storage_path=".memory/chroma")

    # Start the API gateway
    api_gateway = APIGateway(tool_registry, memory_service)
    import uvicorn
    uvicorn.run(api_gateway.app, host="127.0.0.1", port=6000)