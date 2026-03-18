import threading
import time
import psutil

# A hypothetical array of known malicious command-and-control server IPs
# In a real scenario, this would dynamically update from Threat Intelligence feeds.
MALICIOUS_IPS = {
    "198.51.100.1",
    "203.0.113.50",
    "192.0.2.100"
}

class NetworkMonitorThread(threading.Thread):
    def __init__(self, toggle_event):
        super().__init__()
        self.toggle_event = toggle_event
        self.daemon = True
        
    def run(self):
        print("[NETWORK-MONITOR] Network Protection thread started.")
        while True:
            # Wait until the toggle is switched ON
            self.toggle_event.wait()
            
            try:
                # Check active network connections
                connections = psutil.net_connections(kind='inet')
                for conn in connections:
                    # Ignore connections that aren't established or don't have remote endpoints
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        remote_ip = conn.raddr.ip
                        if remote_ip in MALICIOUS_IPS:
                            pid = conn.pid
                            if pid:
                                try:
                                    process = psutil.Process(pid)
                                    process_name = process.name()
                                    print(f"[NETWORK-MONITOR] Malicious connection detected! IP: {remote_ip}. Terminating process: {process_name} (PID: {pid})")
                                    # Terminate the offending process
                                    process.terminate()
                                    # Optional: wait for process to die or force kill
                                    # process.wait(timeout=3)
                                except psutil.NoSuchProcess:
                                    pass
                                except psutil.AccessDenied:
                                    print(f"[NETWORK-MONITOR] Access denied while trying to terminate PID: {pid}")
            except Exception as e:
                pass
            
            # Sleep briefly to prevent high CPU usage
            time.sleep(2)

def start_network_monitor(toggle_event):
    """Starts the background thread that constantly monitors active internet connections."""
    monitor = NetworkMonitorThread(toggle_event)
    monitor.start()
    return monitor
