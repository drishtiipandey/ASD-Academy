
import os, json, time
from .utils import write_json, safe_write, timestamp

REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")

def save_json_report(name: str, data: dict):
    path = os.path.join(REPORT_DIR, f"{name}_{int(time.time())}.json")
    write_json(path, {"created": timestamp(), "data": data})
    return path

def append_txt_log(name: str, text: str):
    path = os.path.join(LOG_DIR, f"{name}.log")
    safe_write(path, f"[{timestamp()}] {text}")
    return path
