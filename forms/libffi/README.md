# libffi

[libffi](https://github.com/libffi/libffi) 3.8.0 with static callback trampolines.
It supplies the same `libffi.so.8` ABI as Wolfi's package, enabling static
trampolines so callbacks can execute from read-only library code under MDWE.
Its hardening recipe lives in `../hardened-packages/ports/libffi` beside the
other explicitly hardened packages; this form retains its image policy.

## Security Posture

- No service, listener, interpreter, shell or runtime allowance.
- Callback code comes from the verified library; callback parameters stay writable.
- Langflow grants native access only within its own service.
- The port overlays Wolfi's library. Library fixes require rebuilding this form.

## Testing

Both Langflow native suites exercise a real callback, assert that MDWE is enabled,
and reject writable executable mappings before testing ONNX inference and embeddings.
