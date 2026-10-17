"""Port LangChain type annotations to Python 3.15 deferred evaluation."""
import re
import sys
from pathlib import Path

site = Path(sys.argv[1])
for package in ("langchain", "langchain_classic"):
    path = site / package / "chains/base.py"
    if not path.exists():
        continue
    source = path.read_text()
    # Chain.dict shadows the builtin in the class namespace. Python 3.15
    # defers annotations, so Pydantic now evaluates metadata's dict[T, U]
    # with that method in scope. Qualifying the builtin preserves the type.
    if "    def dict(" not in source:
        continue
    source, count = re.subn(r"(?<![\w.])dict\[", "builtins.dict[", source)
    if count and "import builtins" not in source:
        raise RuntimeError(f"{path}: expected upstream builtins import")
    path.write_text(source)
    print(f"{package}: qualified {count} dictionary annotations")
