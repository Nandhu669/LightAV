import threading

# GUI → Engine control event
# When set: workers process files
# When cleared: workers pause and wait
RUNNING = threading.Event()
RUNNING.set()  # Start in running state by default
