import time
from datetime import datetime

def get_current_timestamp() -> str:
    """
    Generates a standardized string timestamp for logging.
    Example: 2026-05-20 10:10:00
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_epoch_time() -> float:
    """
    Returns the current UNIX epoch time. Handy for threshold calculations and sliding windows.
    """
    return time.time()

def has_duration_passed(start_time: float, duration_seconds: float) -> bool:
    """
    Checks if a certain duration of seconds has elapsed since start_time.
    """
    return (get_epoch_time() - start_time) >= duration_seconds