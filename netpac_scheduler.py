#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

import logging
from netpac import scheduler, load_jobs_from_db, scheduler_logger, cleanup_job_history
import time

aps_logger = logging.getLogger('apscheduler')
aps_logger.propagate = False
aps_handler = logging.FileHandler('/var/log/netpac/scheduler.log')
aps_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M'))
aps_logger.addHandler(aps_handler)
aps_logger.setLevel(logging.WARNING)

HISTORY_CLEANUP_INTERVAL = 24 * 3600

if __name__ == "__main__":
    scheduler.resume()
    load_jobs_from_db()
    scheduler_logger.info("Standalone scheduler process resumed and active")
    
    last_cleanup = 0.0

    try:
        while True:
            if time.time() - last_cleanup >= HISTORY_CLEANUP_INTERVAL:
                cleanup_job_history()
                last_cleanup = time.time()
            time.sleep(30)
            scheduler.wakeup()
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()