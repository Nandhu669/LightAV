import psutil
import socket

def start_network_scan():
    """
    Scans active network connections and identifies potential risks.
    """
    results = []
    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.status == 'LISTEN' or conn.raddr:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                
                risk = "Low"
                # Flag common high-risk ports if they are listening
                if conn.status == 'LISTEN':
                    high_risk_ports = [21, 22, 23, 445, 3389]
                    if conn.laddr.port in high_risk_ports:
                        risk = "Medium"
                
                results.append({
                    "local_address": laddr,
                    "remote_address": raddr,
                    "status": conn.status,
                    "pid": conn.pid,
                    "risk": risk
                })
        
        return {"success": True, "connections": results}
    except Exception as e:
        return {"success": False, "error": str(e)}

if __name__ == "__main__":
    print(start_network_scan())
