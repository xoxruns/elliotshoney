from qdrant_client import QdrantClient
import os


qdrant_client = QdrantClient(
    url="https://d4eac50d-6ba0-45f4-8fae-f83a7596c55d.eu-west-1-0.aws.cloud.qdrant.io:6333/", 
    api_key=os.getenv("QDRANT_API_KEY"),
)

print(qdrant_client.get_collections())