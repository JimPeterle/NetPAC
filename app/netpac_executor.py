#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from netpac import run_executor, exec_logger

if __name__ == "__main__":
    try:
        run_executor()
    except (KeyboardInterrupt, SystemExit):
        exec_logger.info("Executor stopped")
