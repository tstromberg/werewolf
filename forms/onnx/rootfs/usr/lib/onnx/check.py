"""Fixed CPU inference checks; no downloaded model, provider, or executable."""
import importlib.metadata
import sys
import numpy as np
import onnxruntime as ort

case = sys.argv[1]
if case == "version":
    assert sys.version_info[:2] == (3, 15)
    assert ort.__version__ == importlib.metadata.version("onnxruntime")
elif case == "providers":
    assert "CPUExecutionProvider" in ort.get_available_providers()
else:
    options = ort.SessionOptions()
    options.intra_op_num_threads = 1
    options.inter_op_num_threads = 1
    session = ort.InferenceSession("/usr/lib/onnx/mul.onnx", options, providers=["CPUExecutionProvider"])
    value = np.array([[1, 2], [3, 4], [5, 6]], dtype=np.float32)
    if case == "inference":
        actual = session.run(None, {"X": value})[0]
        np.testing.assert_array_equal(actual, value * value)
    elif case == "shape":
        try:
            session.run(None, {"X": np.ones((1, 1), dtype=np.float32)})
        except ort.capi.onnxruntime_pybind11_state.InvalidArgument:
            pass
        else:
            raise AssertionError("invalid shape accepted")
    elif case == "input":
        try:
            session.run(None, {"unrecognized": value})
        except ValueError:
            pass
        else:
            raise AssertionError("unknown input accepted")
    else:
        raise AssertionError("unknown check")
print("onnx-" + case + ": ok")
