# MiniLM ONNX model

Read-only all-MiniLM-L6-v2 model and tokenizer used by Langflow's default Chroma
embedding function. Both Langflow forms compose this data-only form with `onnx`.

The model archive is pinned to Chroma's verification hash. Only its six inference
files and the Apache 2.0 license are installed, under
`/usr/share/onnx/minilm-l6-v2/onnx`. No service, listener, interpreter, downloader
or runtime allowance is added.

Langflow's native test verifies offline 384-dimensional embeddings, normalization,
repeatability and distinct results for distinct input. Applications can compose
`onnx` alone when they supply another model.
