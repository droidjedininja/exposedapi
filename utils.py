import time

def sleep(seconds):
    try:
        time.sleep(seconds)
    except KeyboardInterrupt:
        pass
