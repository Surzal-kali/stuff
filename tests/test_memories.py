from pathlib import Path

from memories import MemoryService


def test_memory_service_round_trip(tmp_path):
    service = MemoryService(storage_path=str(tmp_path / "chroma"))

    service.remember(
        namespace="intel",
        memory_id="scan-001",
        text="public ssh service exposed on 10.0.0.8",
        embedding=[0.1, 0.2, 0.3],
        source="scanner",
    )

    hits = service.recall(namespace="intel", query_embedding=[0.1, 0.2, 0.3], limit=5)
    keyword_hits = service.search(namespace="intel", query_text="ssh", limit=5)

    assert hits
    assert hits[0]["id"] == "scan-001"
    assert keyword_hits
    assert keyword_hits[0]["id"] == "scan-001"
    assert "intel" in service.list_namespaces()
