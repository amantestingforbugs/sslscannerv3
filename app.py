"""app.py — SSL Sentinel v3 entry point."""
import os, sys, logging
from pathlib import Path
from flask import Flask, render_template

sys.path.insert(0, str(Path(__file__).parent))

from db.database import init_db
from api.routes import api
from scheduler.runner import start_scheduler
from subfinder.runner import start_subfinder_scheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout),
              logging.FileHandler("data/sentinel.log")],
)

Path("data").mkdir(exist_ok=True)
app = Flask(__name__, template_folder="templates", static_folder="static")
app.register_blueprint(api)

@app.get("/")
def index(): return render_template("index.html")

@app.get("/favicon.ico")
def favicon(): return "", 204

if __name__ == "__main__":
    init_db()
    start_scheduler()
    start_subfinder_scheduler()
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
