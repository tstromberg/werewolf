"""Load Wolfi's pure Python web packages with the hardened interpreter."""
import sys

# Wolfi currently packages Flask and Gunicorn under the Python 3.13 stream.
sys.path.insert(0, "/usr/lib/python3.13/site-packages")

from gunicorn.app.wsgiapp import run

run()
