import json
import os
import uuid
from typing import List

import pandas as pd
from qdrant_client import QdrantClient
from qdrant_client.http.models import Distance, VectorParams, PointStruct
from sentence_transformers import SentenceTransformer

from . import IVectorstore

sentence_transformer_ef = SentenceTransformer("WhereIsAI/UAE-Large-V1")


class Qdrant(IVectorstore):
    def __init__(self, config=None):
        if config is not None:
            self.embedding_function = config.get(
                "embedding_function", sentence_transformer_ef
            )
            self.dimension = config.get("dimension", 1024)
            qdrant_client_options = config.get("qdrant_client_options", {})
        else:
            self.embedding_function = sentence_transformer_ef
            self.dimension = 1024
            qdrant_client_options = {}
        self.client = QdrantClient(**qdrant_client_options)
        self._init_collections()

    def _init_collections(self):
        for name in ["sql", "ddl", "documentation"]:
            if not self.client.collection_exists(collection_name=name):
                self.client.create_collection(
                    collection_name=name,
                    vectors_config=VectorParams(
                        size=self.dimension, distance=Distance.COSINE
                    ),
                )

    def index_question_sql(self, question: str, sql: str, **kwargs) -> str:
        question_sql_json = json.dumps(
            {"question": question, "sql": sql}, ensure_ascii=False
        )
        chunk_id = str(uuid.uuid4())
        vector = self.embedding_function.encode([question_sql_json])[0]
        self.client.upsert(
            collection_name="sql",
            points=[
                PointStruct(
                    id=chunk_id, vector=vector, payload={"data": question_sql_json}
                )
            ],
        )
        return chunk_id + "-sql"

    def index_ddl(self, ddl: str, **kwargs) -> str:
        chunk_id = str(uuid.uuid4())
        table = kwargs.get("table", None)
        vector = self.embedding_function.encode([ddl])[0]
        payload = {"data": ddl}
        if table:
            payload["table_name"] = table
        self.client.upsert(
            collection_name="ddl",
            points=[PointStruct(id=chunk_id, vector=vector, payload=payload)],
        )
        return chunk_id + "-ddl"

    def index_documentation(self, documentation: str, **kwargs) -> str:
        chunk_id = str(uuid.uuid4())
        vector = self.embedding_function.encode([documentation])[0]
        self.client.upsert(
            collection_name="documentation",
            points=[
                PointStruct(id=chunk_id, vector=vector, payload={"data": documentation})
            ],
        )
        return chunk_id + "-doc"

    def fetch_all_vectorstore_data(self, **kwargs) -> pd.DataFrame:
        data = []
        for name in ["sql", "ddl", "documentation"]:
            points = self.client.scroll(collection_name=name, limit=10000)[0]
            for point in points:
                payload = point.payload or {}
                if name == "sql":
                    doc = json.loads(payload.get("data", "{}"))
                    question = doc.get("question")
                    content = doc.get("sql")
                else:
                    question = None
                    content = payload.get("data")
                data.append(
                    {
                        "id": point.id,
                        "question": question,
                        "content": content,
                        "training_data_type": name,
                    }
                )
        return pd.DataFrame(data)

    def delete_vectorstore_data(self, item_id: str, **kwargs) -> bool:
        uuid_str = item_id[:-4]
        if item_id.endswith("-sql"):
            self.client.delete(collection_name="sql", points_selector=[uuid_str])
            return True
        elif item_id.endswith("-ddl"):
            self.client.delete(collection_name="ddl", points_selector=[uuid_str])
            return True
        elif item_id.endswith("-doc"):
            self.client.delete(
                collection_name="documentation", points_selector=[uuid_str]
            )
            return True
        else:
            return False

    def remove_collection(self, collection_name: str) -> bool:
        if self.client.collection_exists(collection_name=collection_name):
            self.client.delete_collection(collection_name=collection_name)
            self.client.create_collection(
                collection_name=collection_name,
                vectors_config=VectorParams(
                    size=self.dimension, distance=Distance.COSINE
                ),
            )
            return True
        return False

    def retrieve_relevant_question_sql(self, question: str, **kwargs) -> list:
        n = kwargs.get("n_results", 2)
        vector = self.embedding_function.encode([question])[0]
        hits = self.client.query_points(
            collection_name="sql", query=vector, limit=n
        ).points
        results = []
        for hit in hits:
            doc = json.loads(hit.payload.get("data", "{}"))
            results.append(doc)
        return results

    def retrieve_relevant_ddl(self, question: str, **kwargs) -> list:
        n = kwargs.get("n_results", 2)
        vector = self.embedding_function.encode([question])[0]
        hits = self.client.query_points(
            collection_name="ddl", query=vector, limit=n
        ).points
        return [hit.payload.get("data") for hit in hits]

    def retrieve_relevant_documentation(self, question: str, **kwargs) -> list:
        n = kwargs.get("n_results", 2)
        vector = self.embedding_function.encode([question])[0]
        hits = self.client.query_points(
            collection_name="documentation", query=vector, limit=n
        ).points
        return [hit.payload.get("data") for hit in hits]
