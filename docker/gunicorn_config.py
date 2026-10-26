import multiprocessing
import os

dir_path = os.path.dirname(os.path.realpath(__file__))

bind = "127.0.0.1:8443"
workers = int(os.environ.get("GUNICORN_WORKERS") or multiprocessing.cpu_count() * 2 + 1)
worker_class = "sync"
timeout = 300
keepalive = 5

accesslog = "/var/log/netpac/gunicorn_access.log"
errorlog = "/var/log/netpac/gunicorn_error.log"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190

proc_name = "netpac-web"
pidfile = f"{dir_path}/gunicorn.pid"
