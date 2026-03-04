import importlib.util
import os
import sys


def _load_backend_app():
    backend_app_path = os.path.join(os.path.dirname(__file__), "backend", "app.py")
    backend_dir = os.path.dirname(backend_app_path)
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)
    spec = importlib.util.spec_from_file_location("hyperfit_backend_app", backend_app_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load backend app module")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


app = _load_backend_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
