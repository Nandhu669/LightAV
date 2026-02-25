import threading

# GUI → Engine control event
# When set: workers process files
# When cleared: workers pause and wait
RUNNING = threading.Event()
RUNNING.set()  # Start in running state by default

# USB Protection state
USB_PROTECTION_ENABLED = threading.Event()
USB_PROTECTION_ENABLED.set() # Enabled by default
