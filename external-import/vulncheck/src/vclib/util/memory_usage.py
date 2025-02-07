import os

import psutil

max_mem = 0


def log_memory_usage(logger=None):
    global max_mem

    process = psutil.Process(os.getpid())
    initial_memory = process.memory_info().rss
    memory_mb = initial_memory / (1024 * 1024)
    if memory_mb > max_mem:
        max_mem = memory_mb
    log_string = f"Current: {memory_mb:.2f} MB -- Max: {max_mem:.2f} MB"

    print(log_string) if logger is None else logger.info(log_string)


def reset_max_mem():
    global max_mem
    max_mem = 0
