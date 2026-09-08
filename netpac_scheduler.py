#!/usr/bin/env python3
import sys
sys.path.insert(0, '/home/netpac/bin/NetPAC')

import logging
from netpac import scheduler, load_jobs_from_db, scheduler_logger
import time

aps_logger = logging.getLogger('apscheduler')
aps_logger.propagate = False
aps_handler = logging.FileHandler('/var/log/netpac/scheduler.log')
aps_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M'))
aps_logger.addHandler(aps_handler)
aps_logger.setLevel(logging.WARNING)

if __name__ == "__main__":
    scheduler.resume()
    load_jobs_from_db()
    scheduler_logger.info("Standalone scheduler process resumed and active")
    
    try:
        while True:
            time.sleep(30)
            load_jobs_from_db()
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()