import os
import sys
import logging
from pathlib import Path
from flask import Flask, render_template

# ✅ PRO SAFE log path setup
log_path = Path(os.getenv("SENTINEL_LOG_PATH", "data/sentinel.log"))
log_path.parent.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(Path(__file__).parent))

from db.database import init_db
from api.routes import api
from scheduler.runner import start_scheduler
from subfinder.runner import start_subfinder_scheduler

# ✅ Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_path)
    ],
)

log = logging.getLogger(__name__)
_bootstrapped = False


def bootstrap_app():
    """Initialize persistent storage and background workers once per process.

    Production runs the app through Gunicorn (``app:app``), which imports this
    module instead of executing the ``__main__`` block. Keeping startup here
    prevents fresh deployments from serving requests before the SQLite schema
    exists, and ensures schedulers are alive in the worker process.
    """
    global _bootstrapped
    if _bootstrapped:
        return
    init_db()
    start_scheduler()
    start_subfinder_scheduler()
    _bootstrapped = True
    log.info("Application bootstrap complete")


app = Flask(__name__, template_folder="templates", static_folder="static")
app.register_blueprint(api)
bootstrap_app()


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/favicon.ico")
def favicon():
    return "", 204


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
