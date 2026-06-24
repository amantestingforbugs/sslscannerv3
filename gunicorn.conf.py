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
