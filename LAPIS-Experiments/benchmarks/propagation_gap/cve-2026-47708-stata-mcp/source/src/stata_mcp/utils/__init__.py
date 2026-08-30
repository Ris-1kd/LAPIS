import platform
from datetime import datetime


def set_config(key, value):
    with open(".env", "w+", encoding="utf-8") as f:
        f.write(f"{key}={value}")
    return {key: value}


def get_nowtime():
    return datetime.strftime(datetime.now(), "%Y%m%d%H%M%S")


def get_os():
    return platform.system()
