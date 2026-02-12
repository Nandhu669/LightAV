import { useState, useEffect } from 'react'
import './App.css'
import { QWebChannel } from './qwebchannel.js'

function App() {
  const [status, setStatus] = useState({ running: false })
  const [quarantine, setQuarantine] = useState([])
  const [logs, setLogs] = useState([])
  const [scanPath, setScanPath] = useState('')
  const [message, setMessage] = useState('')
  const [cpuPercent, setCpuPercent] = useState(0)
  const [ramPercent, setRamPercent] = useState(0)
  const [progress, setProgress] = useState({ current: 0, total: 100, visible: false })
  const [scanHistory, setScanHistory] = useState([])
  const [pybridge, setPybridge] = useState(null)
  const [activeView, setActiveView] = useState('dashboard')

  const logRemote = (msg) => {
    fetch('/api/log', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ msg })
    }).catch(() => { })
  }

  useEffect(() => {
    logRemote('React App mounted')
    addLog('System initialized', 'INFO')
    fetchStatus()
    fetchQuarantine()
    const interval = setInterval(() => {
      fetchSystemStats()
    }, 2000)

    const initBridge = (retries = 5) => {
      if (typeof qt !== 'undefined') {
        new QWebChannel(qt.webChannelTransport, (channel) => {
          const bridge = channel.objects.pybridge;
          setPybridge(bridge);
          bridge.log('Native bridge connected from JS');
          addLog('Native bridge connected', 'INFO');
        });
      } else if (retries > 0) {
        setTimeout(() => initBridge(retries - 1), 500);
      }
    };

    initBridge();
    return () => clearInterval(interval)
  }, [])

  const fetchStatus = async () => {
    const res = await fetch('/api/status')
    const data = await res.json()
    setStatus(data)
  }

  const fetchQuarantine = async () => {
    const res = await fetch('/api/quarantine')
    const data = await res.json()
    setQuarantine(data.files || [])
  }

  const fetchSystemStats = async () => {
    try {
      const res = await fetch('/api/system_stats')
      const data = await res.json()
      setCpuPercent(data.cpu || 0)
      setRamPercent(data.ram || 0)
    } catch (e) { }
  }

  const addLog = (msg, level = 'INFO') => {
    const time = new Date().toLocaleTimeString()
    setLogs(prev => [...prev.slice(-50), { time, msg, level }])
  }

  const toggleProtection = async () => {
    await fetch('/api/toggle', { method: 'POST' })
    fetchStatus()
    addLog(status.running ? 'Protection paused' : 'Protection started', 'INFO')
  }

  const selectFile = () => {
    if (pybridge) {
      pybridge.select_file((path) => {
        if (path) {
          setScanPath(path)
          scanFile(path)
        }
      });
    } else {
      const path = prompt('Enter file path to scan:')
      if (path) {
        setScanPath(path)
        scanFile(path)
      }
    }
  }

  const selectFolder = () => {
    if (pybridge) {
      pybridge.select_folder((path) => {
        if (path) {
          scanFolder(path)
        }
      });
    } else {
      const path = prompt('Enter folder path to scan:')
      if (path) {
        scanFolder(path)
      }
    }
  }

  const scanFile = async (path = scanPath) => {
    if (!path) return
    setMessage('Scanning file...')
    addLog(`Scanning file: ${path}`, 'INFO')
    setProgress({ current: 0, total: 100, visible: true })

    const progressInterval = setInterval(() => {
      setProgress(prev => {
        if (prev.current < 90) return { ...prev, current: prev.current + 5 }
        return prev
      })
    }, 200)

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path })
      })
      clearInterval(progressInterval)
      setProgress({ current: 100, total: 100, visible: true })

      const data = await res.json()
      if (data.success) {
        const level = data.verdict === 'MALICIOUS' ? 'THREAT' : 'INFO'
        addLog(`${data.verdict}: ${path}`, level)
        setScanHistory(prev => [{ path, verdict: data.verdict, time: new Date().toLocaleTimeString() }, ...prev.slice(0, 10)])
        setMessage(`Scan complete: ${data.verdict}`)
      } else {
        addLog(`Error: ${data.error}`, 'WARNING')
        setMessage(`Error: ${data.error}`)
      }
    } catch (e) {
      clearInterval(progressInterval)
      addLog(`Fetch error: ${e.message}`, 'ERROR')
      setMessage(`Connection error: ${e.message}`)
    } finally {
      setTimeout(() => setProgress(prev => ({ ...prev, visible: false })), 1000)
      fetchQuarantine()
    }
  }

  const scanFolder = async (path) => {
    setMessage('Scanning folder...')
    addLog(`Scanning folder: ${path}`, 'INFO')
    setProgress({ current: 0, total: 100, visible: true })

    const progressInterval = setInterval(() => {
      setProgress(prev => {
        if (prev.current < 95) return { ...prev, current: prev.current + 2 }
        return prev
      })
    }, 500)

    try {
      const res = await fetch('/api/scan_folder', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path })
      })
      clearInterval(progressInterval)
      setProgress({ current: 100, total: 100, visible: true })

      const data = await res.json()
      if (data.success) {
        addLog(`Folder scan complete. Found ${data.threats_found} threats in ${path}`, data.threats_found > 0 ? 'THREAT' : 'INFO')
        setScanHistory(prev => [{ path, verdict: data.threats_found > 0 ? 'INFECTED' : 'CLEAN', time: new Date().toLocaleTimeString() }, ...prev.slice(0, 10)])
        setMessage(`Scan complete: ${data.threats_found} threats found`)
      } else {
        addLog(`Error: ${data.error}`, 'WARNING')
        setMessage(`Error: ${data.error}`)
      }
    } catch (e) {
      clearInterval(progressInterval)
      addLog(`Fetch error: ${e.message}`, 'ERROR')
      setMessage(`Connection error: ${e.message}`)
    } finally {
      setTimeout(() => setProgress(prev => ({ ...prev, visible: false })), 1000)
      fetchQuarantine()
    }
  }

  const renderView = () => {
    switch (activeView) {
      case 'dashboard':
        return (
          <div className="view-dashboard">
            <div className="status-grid-top">
              <div className={`card-protected-main ${status.running ? 'active' : 'inactive'}`}>
                <div className={`status-badge ${status.running ? 'active' : 'paused'}`}>
                  ● {status.running ? 'Active' : 'Paused'}
                </div>
                <div className="card-icon-large">{status.running ? '🛡️' : '⚠️'}</div>
                <h1>{status.running ? "You're Protected" : "Security Paused"}</h1>
                <p>{status.running ? "All security features are active and running" : "Enable protection to secure your system"}</p>
                <div className="protection-level">
                  <div className="level-header">
                    <span>Protection Level</span>
                    <span>{status.running ? 'Maximum' : 'None'}</span>
                  </div>
                  <div className="level-bar-container">
                    <div className="level-bar" style={{ width: status.running ? '100%' : '10%' }}></div>
                  </div>
                </div>
                <div className="card-footer-stats">
                  <div className="f-stat">
                    <span>Last Activity</span>
                    <strong>{scanHistory[0] ? scanHistory[0].time : 'Never'}</strong>
                  </div>
                  <div className="f-stat">
                    <span>Current Threats</span>
                    <strong>{quarantine.length} isolated</strong>
                  </div>
                </div>
              </div>

              <div className="status-tiles">
                <div className="tile-card">
                  <div className={`tile-icon ${status.running ? '' : 'warning'}`}>{status.running ? '🕒' : '🚫'}</div>
                  <div className="tile-label">Active Monitoring</div>
                  <div className="tile-value">{status.running ? '24/7' : 'OFF'}</div>
                  <div className="tile-sub">{status.running ? 'Continuous protection enabled' : 'Service is currently disabled'}</div>
                  <div className="tile-badge">{status.running ? 'Real-time' : 'Inactive'}</div>
                </div>
                <div className="tile-card">
                  <div className="tile-icon">🔒</div>
                  <div className="tile-label">System Firewall</div>
                  <div className="tile-value protected">{status.running ? 'Protected' : 'Standard'}</div>
                  <div className="tile-sub">Network monitoring {status.running ? 'active' : 'limited'}</div>
                  <div className="tile-badge secure">Secure</div>
                </div>
                <div className="tile-card">
                  <div className="tile-icon warning">⚠️</div>
                  <div className="tile-label">Quarantined Files</div>
                  <div className="tile-value">{quarantine.length}</div>
                  <div className="tile-sub">{quarantine.length > 0 ? 'Review isolated threats' : 'Your system is clean'}</div>
                  <div className="tile-badge monitored">Detected</div>
                </div>
                <div className="tile-card">
                  <div className="tile-icon success">🧬</div>
                  <div className="tile-label">Engine Version</div>
                  <div className="tile-value">v1.2.4</div>
                  <div className="tile-sub">Heuristics: Active</div>
                  <div className="tile-badge updated">Latest</div>
                </div>
              </div>
            </div>

            <div className="quick-scan-tray">
              <div className="section-header">
                <h2>🔍 Scan Your System</h2>
              </div>
              <div className="scan-content-mini">
                <p>{message || 'Ready to scan system areas'}</p>
                {progress.visible && (
                  <div className="progress-bar-mini">
                    <div className="progress-fill" style={{ width: `${(progress.current / progress.total) * 100}%` }}></div>
                  </div>
                )}
                <div className="scan-actions-mini">
                  <button onClick={selectFile}>Quick Scan</button>
                  <button onClick={selectFolder} className="btn-secondary">Custom Scan</button>
                </div>
              </div>
            </div>
          </div>
        )
      case 'scan':
        return (
          <div className="view-scan">
            <div className="section-header">
              <h2>Select Scan Type</h2>
            </div>
            <div className="scan-grid">
              <div className="scan-card active">
                <div className="scan-icon">⚡</div>
                <h3>Quick Scan</h3>
                <p>Fast scan of critical system areas</p>
                <div className="scan-duration">Duration: ~2 min</div>
                <button onClick={selectFile}>Start Scan</button>
              </div>
              <div className="scan-card">
                <div className="scan-icon">🔍</div>
                <h3>Full System Scan</h3>
                <p>Complete deep scan of all files</p>
                <div className="scan-duration">Duration: ~45 min</div>
                <button className="btn-outline">Start Scan</button>
              </div>
              <div className="scan-card">
                <div className="scan-icon">📁</div>
                <h3>Custom Scan</h3>
                <p>Select specific files and folders</p>
                <div className="scan-duration">Duration: Varies</div>
                <button onClick={selectFolder} className="btn-outline">Start Scan</button>
              </div>
              {['Vulnerability Scan', 'External Devices', 'Network Scan'].map((type, i) => (
                <div key={i} className="scan-card">
                  <div className="scan-icon">🛡️</div>
                  <h3>{type}</h3>
                  <p>Comprehensive security check</p>
                  <button className="btn-outline">Start Scan</button>
                </div>
              ))}
            </div>
          </div>
        )
      case 'protection':
        return (
          <div className="view-protection">
            <div className="section-header">
              <h2>Protection Center</h2>
            </div>
            <div className="protection-list">
              {[
                { name: 'Real-Time Protection', desc: 'Continuously monitors and blocks threats in real-time', status: 'Excellent' },
                { name: 'Web Protection', desc: 'Blocks malicious websites and phishing attempts', status: 'Excellent' },
                { name: 'Download Protection', desc: 'Automatically scans all downloaded files', status: 'Good' },
                { name: 'Ransomware Shield', desc: 'Advanced protection against ransomware attacks', status: 'Excellent', premium: true },
                { name: 'Network Protection', desc: 'Monitors network traffic for suspicious activity', status: 'Good' },
                { name: 'Privacy Guard', desc: 'Protects your personal data and prevents tracking', premium: true },
                { name: 'Firewall Control', desc: 'Advanced firewall with custom rules', status: 'Excellent' },
                { name: 'Email Protection', desc: 'Detects threats in attachments and links' },
              ].map((item, i) => (
                <div key={i} className="protection-item">
                  <div className="p-icon">🛡️</div>
                  <div className="p-info">
                    <div className="p-title">
                      {item.name}
                      {item.status && <span className={`p-badge ${item.status.toLowerCase()}`}>● {item.status}</span>}
                      {item.premium && <span className="p-premium">Premium</span>}
                    </div>
                    <div className="p-desc">{item.desc}</div>
                  </div>
                  <div className="p-toggle">
                    <label className="switch">
                      <input type="checkbox" checked={status.running && !item.premium} readOnly={item.premium} />
                      <span className="slider round"></span>
                    </label>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )
      case 'performance':
        return (
          <div className="view-performance">
            <div className="section-header">
              <h2>System Performance</h2>
              <div className="perf-score">Performance Score <span>95</span></div>
            </div>
            <div className="perf-grid">
              <div className="perf-card">
                <div className="perf-icon cpu">💻</div>
                <div className="perf-info">
                  <div className="p-label">CPU Usage</div>
                  <div className="p-status-text success">Optimal</div>
                </div>
                <div className="p-value">{cpuPercent.toFixed(1)}%</div>
                <div className="p-bar-container"><div className="p-bar" style={{ width: `${cpuPercent}%` }}></div></div>
              </div>
              <div className="perf-card">
                <div className="perf-icon ram">🧠</div>
                <div className="perf-info">
                  <div className="p-label">Memory Usage</div>
                  <div className="p-status-text success">Good</div>
                </div>
                <div className="p-value">{ramPercent.toFixed(1)}%</div>
                <div className="p-bar-container"><div className="p-bar" style={{ width: `${ramPercent}%` }}></div></div>
              </div>
            </div>
          </div>
        )
      case 'history':
        return (
          <div className="view-history">
            <div className="section-header">
              <h2>Threat Detection Log</h2>
              <div className="header-buttons">
                <button className="btn-outline btn-sm" onClick={() => { if (confirm('Clear all scan history?')) setScanHistory([]); }}>🗑️ Clear History</button>
                <button className="btn-text">View All 👤</button>
              </div>
            </div>
            <div className="history-list">
              {scanHistory.map((item, i) => (
                <div key={i} className={`history-item ${item.verdict.toLowerCase()}`}>
                  <div className="h-icon">{item.verdict === 'MALICIOUS' ? '❌' : '✅'}</div>
                  <div className="h-info">
                    <div className="h-title">{item.verdict}: {item.path.split('\\').pop()}</div>
                    <div className="h-time">{item.time}</div>
                    <div className="h-path">{item.path}</div>
                  </div>
                  <div className="h-actions">
                    <span className={`h-badge ${item.verdict.toLowerCase()}`}>{item.verdict === 'MALICIOUS' ? 'BLOCKED' : 'CLEANED'}</span>
                  </div>
                </div>
              ))}
              {scanHistory.length === 0 && <div className="empty-message">No scan history available</div>}
            </div>
          </div>
        )
      default:
        return <div className="empty-message">View {activeView} is under construction</div>
    }
  }

  const [showNotifications, setShowNotifications] = useState(false)
  const [showUserMenu, setShowUserMenu] = useState(false)
  const [unreadCount, setUnreadCount] = useState(3)

  const toggleNotifications = () => {
    setShowNotifications(!showNotifications)
    if (!showNotifications) setUnreadCount(0)
    setShowUserMenu(false)
  }

  const toggleUserMenu = () => {
    setShowUserMenu(!showUserMenu)
    setShowNotifications(false)
  }

  return (
    <div className="dashboard-layout">
      <aside className="sidebar">
        <div className="logo"><span className="logo-icon">🛡️</span><h2>Light AV</h2></div>
        <nav>
          {[
            { id: 'dashboard', label: 'Dashboard', icon: '📊' },
            { id: 'scan', label: 'Scan', icon: '🔍' },
            { id: 'protection', label: 'Protection', icon: '🛡️' },
            { id: 'performance', label: 'Performance', icon: '📈' },
            { id: 'history', label: 'History', icon: '🕒' },
            { id: 'reports', label: 'Reports', icon: '📄' },
            { id: 'settings', label: 'Settings', icon: '⚙️' },
            { id: 'help', label: 'Help & Support', icon: '❓' },
          ].map(item => (
            <button key={item.id} className={`nav-item ${activeView === item.id ? 'active' : ''}`} onClick={() => setActiveView(item.id)}>
              <span className="nav-icon">{item.icon}</span>
              <span className="nav-label">{item.label}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className={`status-pill ${status.running ? 'running' : 'paused'}`}><span className="dot"></span>{status.running ? 'Protected' : 'Protection Paused'}</div>
          <button onClick={toggleProtection} className="btn-toggle-main">{status.running ? 'Pause' : 'Start'}</button>
        </div>
      </aside>
      <main className="main-content">
        <header className="main-header">
          <div className="view-title"><h1>Security Dashboard</h1><p>Monitor and manage your security status</p></div>
          <div className="header-actions">
            <div className="notification-bell" onClick={toggleNotifications}>
              🔔 {unreadCount > 0 && <span className="counter">{unreadCount}</span>}

              {showNotifications && (
                <div className="dropdown-menu">
                  <div className="dropdown-header">
                    <span>Notifications</span>
                    <button className="btn-text" onClick={(e) => { e.stopPropagation(); setLogs([]); }}>Clear All</button>
                  </div>
                  <div className="dropdown-list">
                    {logs.slice(-5).reverse().map((log, i) => (
                      <div key={i} className="dropdown-item">
                        <div className="d-icon">{log.level === 'THREAT' ? '❌' : 'ℹ️'}</div>
                        <div className="d-info">
                          <div className="d-title">{log.msg}</div>
                          <div className="d-time">{log.time}</div>
                        </div>
                      </div>
                    ))}
                    {logs.length === 0 && <div className="dropdown-item">No new notifications</div>}
                  </div>
                </div>
              )}
            </div>
            <div className="user-profile" onClick={toggleUserMenu}>
              <span className="avatar">👤</span>
              <span className="username">Admin</span>
              <span className="chevron">{showUserMenu ? '▲' : '▼'}</span>

              {showUserMenu && (
                <div className="dropdown-menu user-menu-dropdown">
                  <div className="dropdown-item" onClick={() => setActiveView('settings')}>
                    <div className="d-icon">⚙️</div>
                    <div className="d-title">Profile Settings</div>
                  </div>
                  <div className="dropdown-item">
                    <div className="d-icon">🔒</div>
                    <div className="d-title">Lock Application</div>
                  </div>
                  <div className="dropdown-item" style={{ borderTop: '1px solid #EEE' }}>
                    <div className="d-icon">🚪</div>
                    <div className="d-title" style={{ color: 'var(--danger)' }}>Admin Logout</div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </header>
        <div className="view-container">{renderView()}</div>
      </main>
    </div>
  )
}

export default App
