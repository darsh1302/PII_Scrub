"""Vector store adapters and the RAG pipeline.

Two adapters by design. Exact search comes first — at a few thousand chunks it is
milliseconds, and it keeps the retrieval lesson unmuddied by approximate recall.
The pgvector adapter follows, and the comparison between them is itself the
deliverable that teaches why vector databases exist.

Similarity is never computed across embedding models; cosine distance between two
embedding spaces is a number with no meaning.
"""
