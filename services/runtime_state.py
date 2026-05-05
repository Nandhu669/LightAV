import threading

# GUI → Engine control event
# When set: workers process files
# When cleared: workers pause and wait
RUNNING = threading.Event()
RUNNING.set()  # Start in running state by default

# USB Protection state
USB_PROTECTION_ENABLED = threading.Event()
USB_PROTECTION_ENABLED.set() # Enabled by default

# Web Protection state
WEB_PROTECTION_ENABLED = threading.Event()
WEB_PROTECTION_ENABLED.set()

# Firewall Protection state
FIREWALL_ENABLED = threading.Event()
FIREWALL_ENABLED.set()

# Network Protection state
NETWORK_PROTECTION_ENABLED = threading.Event()
NETWORK_PROTECTION_ENABLED.set()

# Privacy Guard state
PRIVACY_GUARD_ENABLED = threading.Event()
PRIVACY_GUARD_ENABLED.set()

# Email Protection state
EMAIL_PROTECTION_ENABLED = threading.Event()
EMAIL_PROTECTION_ENABLED.set()
