"""Run the complete upstream ASGI application without a process launcher."""
import os
from pathlib import Path
from lfx.log.logger import configure
import uvicorn
from chromadb.utils.embedding_functions.onnx_mini_lm_l6_v2 import ONNXMiniLM_L6_V2

# Use the packaged model without downloading or writing executable content.
ONNXMiniLM_L6_V2.DOWNLOAD_PATH = Path("/usr/share/onnx/minilm-l6-v2")
configure(log_level=os.environ.get("LANGFLOW_LOG_LEVEL", "info"), log_file=None)
from langflow.main import setup_app

# The upstream CLI starts a multiprocessing supervisor. A single ASGI process
# retains the editor, graph API and inference without granting child execution.
uvicorn.run(
    setup_app(),
    host=os.environ["LANGFLOW_HOST"],
    port=int(os.environ.get("LANGFLOW_PORT", "7860")),
    workers=1,
    reload=False,
    loop="asyncio",
    proxy_headers=False,
    log_level="info",
)
