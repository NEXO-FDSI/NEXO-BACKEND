import httpx
import chromadb

# 1. Verifica embeddings
resp = httpx.post(
    "http://localhost:11434/api/embeddings",
    json={"model": "nomic-embed-text", "prompt": "Phishing via spearphishing attachment"},
    timeout=30,
)
embedding = resp.json()["embedding"]
print(f"Embedding generado: {len(embedding)} dimensiones")

# 2. Verifica Chroma (persistente en disco)
client = chromadb.PersistentClient(path="./data/chroma")
collection = client.get_or_create_collection("test")
collection.add(ids=["1"], embeddings=[embedding], documents=["Phishing via spearphishing attachment"])
result = collection.query(query_embeddings=[embedding], n_results=1)
print("Chroma respondió:", result["documents"])

# 3. Verifica generación con Qwen3
resp = httpx.post(
    "http://localhost:11434/api/generate",
    json={"model": "qwen3:8b", "prompt": "Responde solo con OK si me lees.", "stream": False},
    timeout=60,
)
print("Qwen3 respondió:", resp.json()["response"])