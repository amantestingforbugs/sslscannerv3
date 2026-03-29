import os
bind = f"0.0.0.0:{os.getenv('PORT','5000')}"
workers = 1
worker_class = "gthread"
threads = 8
timeout = 120
graceful_timeout = 30
keepalive = 5
accesslog = "-"
errorlog = "-"
loglevel = "info"

def on_starting(server):
    import sys; sys.path.insert(0, os.path.dirname(__file__))
    from db.database import init_db
    from scheduler.runner import start_scheduler
    from subfinder.runner import start_subfinder_scheduler
    init_db()
    start_scheduler()
    start_subfinder_scheduler()
