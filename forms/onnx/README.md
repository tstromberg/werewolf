# ONNX CPU runtime

[ONNX Runtime](https://onnxruntime.ai/) 1.31.0 built for hardened Python 3.15;
[form.yaml](form.yaml) supplies the runtime for applications such as Langflow.

## Security Posture

- Python comes from the signed hardened feed.
- The image contains no shell, package installer, GPU driver, or model downloader.
- The form opens no listener and grants no outbound network or execution allowance.
- Applications declare their own user, model storage, resources, and network access.

Python is an intentional interpreter weakness. Native CPU inference uses packaged
read-only libraries; this form does not enable arbitrary ctypes library loading.

## Getting Started

See [image availability](../../docs/forms-catalog.md#images-and-downloads).
For a usable editor and inference service, choose the Langflow form. To build a
custom service, compose this runtime and install its Python program in verified root.

```sh
howl create onnx --with onnx --build
```

The runtime alone starts no application. `/usr/bin/python3.15` can import `onnxruntime`;
sessions should select `CPUExecutionProvider`. Store mutable models in the application's
own data directory. See the [Python API
documentation](https://onnxruntime.ai/docs/api/python/api_summary.html).

### Known Quirks

The native extension is built from source because upstream publishes no CPython
3.15 wheel. A small pinned multiplication model and fixed check script verify real
CPU inference, shape validation, and input validation during form testing.
