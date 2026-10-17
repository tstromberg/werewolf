"""Exercise the same Chroma embedding implementation Langflow uses, offline."""
from pathlib import Path
import numpy as np
from chromadb.utils.embedding_functions.onnx_mini_lm_l6_v2 import ONNXMiniLM_L6_V2

ONNXMiniLM_L6_V2.DOWNLOAD_PATH = Path("/usr/share/onnx/minilm-l6-v2")
embedding = ONNXMiniLM_L6_V2(preferred_providers=["CPUExecutionProvider"])
vectors = np.asarray(embedding(["A cat sits on a mat.", "A cat sits on a mat.", "A spaceship approaches Saturn."]))
assert vectors.shape == (3, 384)
assert np.isfinite(vectors).all()
np.testing.assert_allclose(np.linalg.norm(vectors, axis=1), 1, atol=1e-5)
np.testing.assert_allclose(vectors[0], vectors[1], atol=1e-6)
assert not np.allclose(vectors[0], vectors[2])
print("onnx-embedding: ok")
