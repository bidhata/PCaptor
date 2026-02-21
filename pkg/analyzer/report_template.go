package analyzer

import (
	"fmt"
	"strings"
	"time"
)

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PCaptor Analysis Report - {{.FileName}}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --primary: #321fdb;
            --primary-dark: #2819b0;
            --success: #2eb85c;
            --danger: #e55353;
            --warning: #f9b115;
            --info: #39f;
            --light: #ebedef;
            --dark: #3c4b64;
            --body-bg: #f3f4f7;
            --sidebar-bg: #fff;
            --card-bg: #fff;
            --text-primary: #3c4b64;
            --text-secondary: #768192;
            --border: #d8dbe0;
            --shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.05);
            --shadow-lg: 0 1rem 3rem rgba(0, 0, 0, 0.1);
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--body-bg);
            color: var(--text-primary);
            line-height: 1.5;
        }

        /* Layout */
        .wrapper {
            display: flex;
            min-height: 100vh;
        }

        /* Sidebar */
        .sidebar {
            width: 256px;
            background: var(--sidebar-bg);
            border-right: 1px solid var(--border);
            position: fixed;
            height: 100vh;
            overflow-y: auto;
            z-index: 1000;
            display: flex;
            flex-direction: column;
        }

        .sidebar-brand {
            padding: 1.5rem;
            border-bottom: 1px solid var(--border);
            flex-shrink: 0;
        }

        .sidebar-brand h1 {
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--primary);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .sidebar-footer {
            padding: 1rem 1.5rem;
            border-top: 1px solid var(--border);
            position: absolute;
            bottom: 0;
            width: 100%;
            background: var(--sidebar-bg);
        }

        .sidebar-footer .credit {
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-align: center;
        }

        .sidebar-footer .credit a {
            color: var(--primary);
            text-decoration: none;
            font-weight: 600;
        }

        .sidebar-footer .credit a:hover {
            text-decoration: underline;
        }

        .sidebar-nav {
            padding: 1rem 0;
            flex: 1;
            overflow-y: auto;
        }

        .nav-item {
            padding: 0.75rem 1.5rem;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-weight: 500;
            font-size: 0.875rem;
        }

        .nav-item:hover {
            background: var(--light);
            color: var(--primary);
        }

        .nav-item.active {
            background: var(--primary);
            color: white;
            border-left: 3px solid var(--primary-dark);
        }

        .nav-icon {
            font-size: 1.125rem;
            width: 20px;
            text-align: center;
        }

        /* Main Content */
        .main-content {
            flex: 1;
            margin-left: 256px;
            padding: 2rem;
        }

        /* Header */
        .page-header {
            margin-bottom: 2rem;
        }

        .page-header h2 {
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 0.5rem;
        }

        .page-header p {
            color: var(--text-secondary);
            font-size: 0.875rem;
        }

        /* Cards */
        .card-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .card {
            background: var(--card-bg);
            border-radius: 0.5rem;
            border: 1px solid var(--border);
            box-shadow: var(--shadow);
            overflow: hidden;
        }

        .card-body {
            padding: 1.5rem;
        }

        .card-header {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border);
            font-weight: 600;
            font-size: 0.875rem;
            color: var(--text-primary);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        /* Stat Cards */
        .stat-card {
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .stat-content {
            flex: 1;
        }

        .stat-label {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
            font-weight: 600;
            margin-bottom: 0.5rem;
        }

        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--text-primary);
            line-height: 1;
        }

        .stat-icon {
            width: 64px;
            height: 64px;
            border-radius: 0.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2rem;
            opacity: 0.9;
        }

        .stat-icon.primary { background: linear-gradient(135deg, var(--primary), var(--primary-dark)); color: white; }
        .stat-icon.success { background: linear-gradient(135deg, var(--success), #25a244); color: white; }
        .stat-icon.danger { background: linear-gradient(135deg, var(--danger), #d63939); color: white; }
        .stat-icon.warning { background: linear-gradient(135deg, var(--warning), #e09b00); color: white; }
        .stat-icon.info { background: linear-gradient(135deg, var(--info), #2d7fd6); color: white; }

        /* Progress */
        .progress {
            height: 8px;
            background: var(--light);
            border-radius: 4px;
            overflow: hidden;
            margin-top: 1rem;
        }

        .progress-bar {
            height: 100%;
            background: linear-gradient(90deg, var(--primary), var(--primary-dark));
            transition: width 0.3s;
        }

        .progress-bar.success { background: linear-gradient(90deg, var(--success), #25a244); }
        .progress-bar.danger { background: linear-gradient(90deg, var(--danger), #d63939); }
        .progress-bar.warning { background: linear-gradient(90deg, var(--warning), #e09b00); }

        /* Table */
        .table-container {
            overflow-x: auto;
            margin-top: 1rem;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
        }

        thead {
            background: var(--light);
        }

        th {
            padding: 0.75rem 1rem;
            text-align: left;
            font-weight: 600;
            color: var(--text-primary);
            border-bottom: 2px solid var(--border);
            white-space: nowrap;
        }

        td {
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border);
        }

        tbody tr:hover {
            background: var(--light);
        }

        /* Badge */
        .badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            font-size: 0.75rem;
            font-weight: 600;
            border-radius: 0.25rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .badge-primary { background: var(--primary); color: white; }
        .badge-success { background: var(--success); color: white; }
        .badge-danger { background: var(--danger); color: white; }
        .badge-warning { background: var(--warning); color: white; }
        .badge-info { background: var(--info); color: white; }
        .badge-light { background: var(--light); color: var(--text-primary); }
        .badge-high { background: var(--danger); color: white; }
        .badge-medium { background: var(--warning); color: white; }
        .badge-low { background: var(--info); color: white; }
        .badge-protocol { background: var(--primary); color: white; }

        /* Search */
        .search-box {
            margin-bottom: 1rem;
        }

        .search-input {
            width: 100%;
            padding: 0.75rem 1rem;
            border: 1px solid var(--border);
            border-radius: 0.375rem;
            font-size: 0.875rem;
            transition: all 0.2s;
        }

        .search-input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(50, 31, 219, 0.1);
        }

        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 3rem 2rem;
            color: var(--text-secondary);
        }

        .empty-icon {
            font-size: 3rem;
            margin-bottom: 1rem;
            opacity: 0.5;
        }

        /* IRC Styles */
        .irc-container {
            background: var(--card-bg);
            border-radius: 0.5rem;
            overflow: hidden;
        }
        
        .irc-channels {
            display: flex;
            gap: 0.5rem;
            padding: 1rem;
            background: var(--light);
            border-bottom: 1px solid var(--border);
            flex-wrap: wrap;
        }
        
        .irc-channel-btn {
            padding: 0.5rem 1rem;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 0.375rem;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.2s;
            font-size: 0.875rem;
            font-weight: 500;
        }
        
        .irc-channel-btn:hover {
            background: var(--body-bg);
            border-color: var(--primary);
            color: var(--primary);
        }
        
        .irc-channel-btn.active {
            background: var(--primary);
            border-color: var(--primary);
            color: white;
        }
        
        .irc-channel {
            padding: 1rem;
        }
        
        .irc-messages {
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
            line-height: 1.6;
            max-height: 600px;
            overflow-y: auto;
        }
        
        .irc-message {
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            margin-bottom: 0.125rem;
        }
        
        .irc-message:hover {
            background: var(--light);
        }
        
        .irc-time {
            color: var(--text-secondary);
            margin-right: 0.5rem;
        }
        
        .irc-nick {
            color: var(--primary);
            font-weight: 600;
            margin-right: 0.5rem;
        }
        
        .irc-text {
            color: var(--text-primary);
        }
        
        .irc-system {
            color: var(--text-secondary);
            font-style: italic;
        }
        
        .irc-msg-join {
            background: rgba(46, 184, 92, 0.1);
        }
        
        .irc-msg-part, .irc-msg-quit {
            background: rgba(229, 83, 83, 0.1);
        }
        
        .irc-msg-kick {
            background: rgba(229, 83, 83, 0.15);
        }
        
        .irc-msg-topic, .irc-msg-nick {
            background: rgba(51, 153, 255, 0.1);
        }

        /* Password Strength */
        .strength-container {
            width: 100%;
        }
        
        .strength-label {
            display: flex;
            justify-content: space-between;
            font-size: 0.75rem;
            margin-bottom: 0.25rem;
            color: var(--text-secondary);
        }
        
        .strength-bar {
            height: 6px;
            background: var(--light);
            border-radius: 3px;
            overflow: hidden;
        }
        
        .strength-fill {
            height: 100%;
            transition: width 0.3s;
        }
        
        .strength-weak { background: var(--danger); }
        .strength-fair { background: var(--warning); }
        .strength-good { background: var(--info); }
        .strength-strong { background: var(--success); }

        /* Code */
        .code {
            font-family: 'Courier New', monospace;
            background: var(--light);
            padding: 0.125rem 0.375rem;
            border-radius: 0.25rem;
            font-size: 0.875rem;
        }

        /* Summary Grid */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 1.5rem;
        }
        
        .summary-card {
            background: var(--card-bg);
            padding: 1.5rem;
            border-radius: 0.5rem;
            border: 1px solid var(--border);
            box-shadow: var(--shadow);
        }
        
        .summary-card h3 {
            color: var(--primary);
            margin-bottom: 1.5rem;
            font-size: 1.125rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .summary-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.75rem 0;
            border-bottom: 1px solid var(--border);
        }
        
        .summary-item:last-child {
            border-bottom: none;
        }
        
        .summary-label {
            color: var(--text-secondary);
            font-weight: 500;
            font-size: 0.875rem;
        }
        
        .summary-value {
            color: var(--text-primary);
            font-weight: 700;
            font-size: 1.125rem;
        }

        /* Utility */
        .text-muted { color: var(--text-secondary); }
        .text-primary { color: var(--primary); }
        .text-success { color: var(--success); }
        .text-danger { color: var(--danger); }
        .text-warning { color: var(--warning); }
        
        .mb-2 { margin-bottom: 0.5rem; }
        .mb-3 { margin-bottom: 1rem; }
        .mb-4 { margin-bottom: 1.5rem; }

        /* Responsive */
        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-100%);
            }
            
            .main-content {
                margin-left: 0;
            }
            
            .card-grid {
                grid-template-columns: 1fr;
            }
        }

        /* Print */
        @media print {
            .sidebar { display: none; }
            .main-content { margin-left: 0; }
            .card { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="wrapper">
        <!-- Sidebar -->
        <aside class="sidebar">
            <div class="sidebar-brand">
                <h1>🔍 PCaptor</h1>
            </div>
            <nav class="sidebar-nav">
                <div class="nav-item active" onclick="showSection('dashboard')">
                    <span class="nav-icon">📊</span>
                    <span>Dashboard</span>
                </div>
                <div class="nav-item" onclick="showSection('threats')">
                    <span class="nav-icon">⚠️</span>
                    <span>Threats</span>
                </div>
                <div class="nav-item" onclick="showSection('c2')">
                    <span class="nav-icon">🎯</span>
                    <span>C2 Detection</span>
                </div>
                <div class="nav-item" onclick="showSection('beaconing')">
                    <span class="nav-icon">📡</span>
                    <span>Beaconing</span>
                </div>
                <div class="nav-item" onclick="showSection('tunneling')">
                    <span class="nav-icon">🚇</span>
                    <span>Tunneling</span>
                </div>
                <div class="nav-item" onclick="showSection('lateral')">
                    <span class="nav-icon">↔️</span>
                    <span>Lateral Movement</span>
                </div>
                <div class="nav-item" onclick="showSection('exfiltration')">
                    <span class="nav-icon">📤</span>
                    <span>Exfiltration</span>
                </div>
                <div class="nav-item" onclick="showSection('tls')">
                    <span class="nav-icon">🔒</span>
                    <span>TLS Fingerprints</span>
                </div>
                <div class="nav-item" onclick="showSection('stego')">
                    <span class="nav-icon">🖼️</span>
                    <span>Steganography</span>
                </div>
                <div class="nav-item" onclick="showSection('urls')">
                    <span class="nav-icon">🔗</span>
                    <span>HTTP URLs</span>
                </div>
                <div class="nav-item" onclick="showSection('credentials')">
                    <span class="nav-icon">🔑</span>
                    <span>Credentials</span>
                </div>
                <div class="nav-item" onclick="showSection('protocols')">
                    <span class="nav-icon">💬</span>
                    <span>Protocols</span>
                </div>
                <div class="nav-item" onclick="showSection('flows')">
                    <span class="nav-icon">🌐</span>
                    <span>Network Flows</span>
                </div>
            </nav>
            <div class="sidebar-footer">
                <div class="credit">
                    Created by <a href="https://krishnendu.com" target="_blank">Krishnendu Paul</a><br>
                    <a href="https://github.com/bidhata/PCaptor" target="_blank">github.com/bidhata/PCaptor</a>
                </div>
            </div>
        </aside>

        <!-- Main Content -->
        <main class="main-content">
            <!-- Dashboard Section -->
            <div id="dashboard" class="content-section">
                <div class="page-header">
                    <h2>Analysis Dashboard</h2>
                    <p>{{.FileName}} • Generated {{.GeneratedTime}}</p>
                </div>

                <!-- Stat Cards -->
                <div class="card-grid">
                    <div class="card">
                        <div class="card-body stat-card">
                            <div class="stat-content">
                                <div class="stat-label">Total Packets</div>
                                <div class="stat-value">{{.TotalPackets}}</div>
                            </div>
                            <div class="stat-icon primary">📦</div>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-body stat-card">
                            <div class="stat-content">
                                <div class="stat-label">Network Flows</div>
                                <div class="stat-value">{{.TotalFlows}}</div>
                            </div>
                            <div class="stat-icon info">🌐</div>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-body stat-card">
                            <div class="stat-content">
                                <div class="stat-label">Threats Detected</div>
                                <div class="stat-value">{{.TotalThreats}}</div>
                            </div>
                            <div class="stat-icon danger">⚠️</div>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-body stat-card">
                            <div class="stat-content">
                                <div class="stat-label">Credentials Found</div>
                                <div class="stat-value">{{.TotalCredentials}}</div>
                            </div>
                            <div class="stat-icon warning">🔑</div>
                        </div>
                    </div>
                </div>

                <!-- Threat Score Card -->
                <div class="card mb-4">
                    <div class="card-header">
                        <span>Threat Score</span>
                        <span class="badge badge-danger">{{.ThreatScore}}/100</span>
                    </div>
                    <div class="card-body">
                        <div class="progress">
                            <div class="progress-bar danger" style="width: {{.ThreatScore}}%"></div>
                        </div>
                    </div>
                </div>

                <!-- Summary -->
                {{.SummaryHTML}}
            </div>

            <!-- Threats Section -->
            <div id="threats" class="content-section" style="display: none;">
                <div class="page-header">
                    <h2>Security Threats</h2>
                    <p>Detected security issues and anomalies</p>
                </div>

                <div class="card">
                    <div class="card-header">Threat Analysis</div>
                    <div class="card-body">
                        <div class="search-box">
                            <input type="text" class="search-input" placeholder="Search threats..." onkeyup="searchTable('threats-table', this.value)">
                        </div>
                        {{.ThreatsHTML}}
                    </div>
                </div>
            </div>

            <!-- C2 Detection Section -->
            <div id="c2" class="content-section" style="display: none;">
                <div class="page-header">
                    <h2>C2 Detection</h2>
                    <p>Command & Control framework detections</p>
                </div>

                <div class="card">
                    <div class="card-header">C2 Framework Analysis</div>
                    <div class="card-body">
                        <div class="search-box">
                            <input type="text" class="search-input" placeholder="Search C2 detections..." onkeyup="searchTable('c2-table', this.value)">
                        </div>
                        {{.C2HTML}}
                    </div>
                </div>
            </div>

            <!-- Beaconing Section -->
            <div id="beaconing" class="content-section" style="display: none;">
                <div class="page-header">
                    <h2>Beaconing Detection</h2>
                    <p>Statistical analysis of C2 callback patterns</p>
                </div>

                <div class="card">
                    <div class="card-header">Beaconing Patterns</div>
                    <div class="card-body">
                        <div class="search-box">
                            <input type="text" class="search-input" placeholder="Search beaconing..." onkeyup="searchTable('beaconing-table', this.value)">
                        </div>
                        <table id="beaconing-table" class="data-table">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Source IP</th>
                                    <th>Destination IP</th>
                                    <th>Port</th>
                                    <th>Interval</th>
                                    <th>Jitter</th>
                                    <th>Confidence</th>
                                    <th>Packets</th>
                                </tr>
                            </thead>
                            <tbody>
                                {{.BeaconingHTML}}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Tunneling Section -->
            <div id="tunneling" class="content-section" style="display: none;">
                <div class="page-header">
                    <h2>Tunneling Detection</h2>
                    <p>SSH and ICMP tunneling analysis</p>
                </div>

                <!-- SSH Tunnels -->
                <div class="card mb-4">
                    <div class="card-header">SSH Tunnels</div>
                    <div class="card-body">
                        <div class="search-box">
                            <input type="text" class="search-input" placeholder="Search SSH tunnels..." onkeyup="searchTable('ssh-table', this.value)">
                        </div>
                        <table id="ssh-table" class="data-table">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Source IP</th>
                                    <th>Destination IP</th>
                                    <th>Port</th>
                                    <th>Throughput</th>
                                    <th>Packet Rate</th>
                                    <th>Duration</th>
                                    <th>Reason</th>
                                    <th>Confidence</th>
                                </tr>
                            </thead>
                            <tbody>
                                {{.SSHTunnelsHTML}}
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- ICMP Tunnels -->
                <div class="card">
                    <div class="card-header">ICMP Tunnels</div>
                    <div class="card-body">
                        <div class="search-box">
                            <input type="text" class="search-input" placeholder="Search ICMP tunnels..." onkeyup="searchTable('icmp-table', this.value)">
                        </div>
                        <table id="icmp-table" class="data-table">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Source IP</th>
                                    <th>Destination IP</th>
                                    <th>Type</th>
                                    <th>Payload Size</th>
                                    <th>Entropy</th>
                                    <th>Reason</th>
                                    <th>Confidence</th>
                                </tr>
                            </thead>
                            <tbody>
                                {{.ICMPTunnelsHTML}}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Lateral Movement Section -->
            <div id="lateral" class="content-section" style="display: none;">
                <div class="page-header">
                    <h2>Lateral Movement</h2>
                    <p>Detected lateral movement patterns across the network</p>
                </div>

                <div class="card">
                    <div class="card-header">Lateral Movement Analysis</div>
                    <div class="card-body">
                        <div class="search-box">
                            <input type="text" class="search-input" placeholder="Search lateral movement..." onkeyup="searchTable('lateral-table', this.value)">
                        </div>
                        <table id="lateral-table" class="data-table">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Source IP</th>
                                    <th>Target Count</th>
                                    <th>Port</th>
                                    <th>Technique</th>
                                    <th>Targets</th>
                                    <th>Confidence</th>
                                </tr>
                            </thead>
                            <tbody>
                                {{.LateralMovementHTML}}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Exfiltration Section -->
            <div id="exfiltration" class="content-section" style="display: none;">
                <div class="page-header">
                    <h2>Data Exfiltration</h2>
                    <p>Large data uploads and suspicious transfers</p>
                </div>

                <div class="card">
                    <div class="card-header">Exfiltration Analysis</div>
                    <div class="card-body">
                        <div class="search-box">
                            <input type="text" class="search-input" placeholder="Search exfiltration..." onkeyup="searchTable('exfil-table', this.value)">
                        </div>
                        <table id="exfil-table" class="data-table">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Source IP</th>
                                    <th>Destination IP</th>
                                    <th>Port</th>
                                    <th>Bytes Out</th>
                                    <th>Duration</th>
                                    <th>Rate</th>
                                    <th>Method</th>
                                    <th>Confidence</th>
                                </tr>
                            </thead>
                            <tbody>
                                {{.ExfiltrationHTML}}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- TLS Fingerprints Section -->
            <div id="tls" class="content-section" style="display: none;">
                <div class="page-header">
                    <h2>TLS Fingerprints (JA3)</h2>
                    <p>TLS/SSL fingerprinting for encrypted C2 detection</p>
                </div>

                <div class="card">
                    <div class="card-header">JA3 Fingerprint Analysis</div>
                    <div class="card-body">
                        <div class="search-box">
                            <input type="text" class="search-input" placeholder="Search TLS fingerprints..." onkeyup="searchTable('tls-table', this.value)">
                        </div>
                        <table id="tls-table" class="data-table">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Source IP</th>
                                    <th>Destination IP</th>
                                    <th>JA3 Hash</th>
                                    <th>Server Name</th>
                                    <th>TLS Version</th>
                                    <th>Suspicious</th>
                                    <th>Confidence</th>
                                </tr>
                            </thead>
                            <tbody>
                                {{.TLSFingerprintsHTML}}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Steganography Section -->
            <div id="stego" class="content-section" style="display: none;">
                <div class="page-header">
                    <h2>Steganography Detection</h2>
                    <p>Hidden data in images and files</p>
                </div>

                <div class="card">
                    <div class="card-header">Steganography Analysis</div>
                    <div class="card-body">
                        <div class="search-box">
                            <input type="text" class="search-input" placeholder="Search steganography..." onkeyup="searchTable('stego-table', this.value)">
                        </div>
                        <table id="stego-table" class="data-table">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Source IP</th>
                                    <th>Destination IP</th>
                                    <th>Protocol</th>
                                    <th>Filename</th>
                                    <th>File Type</th>
                                    <th>Method</th>
                                    <th>Indicator</th>
                                    <th>Confidence</th>
                                </tr>
                            </thead>
                            <tbody>
                                {{.StegoHTML}}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- URLs Section -->
            <div id="urls" class="content-section" style="display: none;">
                <div class="page-header">
                    <h2>HTTP URLs</h2>
                    <p>All accessed URLs from HTTP traffic</p>
                </div>

                <div class="card">
                    <div class="card-header">URL Analysis</div>
                    <div class="card-body">
                        <div class="search-box">
                            <input type="text" class="search-input" placeholder="Search URLs..." onkeyup="searchTable('urls-table', this.value)">
                        </div>
                        {{.URLsHTML}}
                    </div>
                </div>
            </div>

            <!-- Credentials Section -->
            <div id="credentials" class="content-section" style="display: none;">
                <div class="page-header">
                    <h2>Extracted Credentials</h2>
                    <p>Credentials found in cleartext protocols</p>
                </div>

                <div class="card">
                    <div class="card-header">Credential Analysis</div>
                    <div class="card-body">
                        <div class="search-box">
                            <input type="text" class="search-input" placeholder="Search credentials..." onkeyup="searchTable('credentials-table', this.value)">
                        </div>
                        {{.CredentialsHTML}}
                    </div>
                </div>
            </div>

            <!-- Protocols Section -->
            <div id="protocols" class="content-section" style="display: none;">
                <div class="page-header">
                    <h2>Protocol Analysis</h2>
                    <p>Messages and communications from various protocols</p>
                </div>

                <!-- Protocol Tabs -->
                <div class="card mb-4">
                    <div class="card-header">
                        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                            <button class="badge badge-primary" style="cursor: pointer; padding: 0.5rem 1rem;" onclick="showProtocol('irc')">IRC</button>
                            <button class="badge badge-info" style="cursor: pointer; padding: 0.5rem 1rem;" onclick="showProtocol('snmp')">SNMP</button>
                            <button class="badge badge-success" style="cursor: pointer; padding: 0.5rem 1rem;" onclick="showProtocol('ldap')">LDAP</button>
                            <button class="badge badge-warning" style="cursor: pointer; padding: 0.5rem 1rem;" onclick="showProtocol('sip')">SIP</button>
                            <button class="badge badge-danger" style="cursor: pointer; padding: 0.5rem 1rem;" onclick="showProtocol('xmpp')">XMPP</button>
                            <button class="badge badge-light" style="cursor: pointer; padding: 0.5rem 1rem;" onclick="showProtocol('tftp')">TFTP</button>
                            <button class="badge badge-primary" style="cursor: pointer; padding: 0.5rem 1rem;" onclick="showProtocol('syslog')">Syslog</button>
                        </div>
                    </div>
                </div>

                <!-- IRC -->
                <div id="protocol-irc" class="protocol-content">
                    <div class="card">
                        <div class="card-header">IRC Chat Messages</div>
                        <div class="card-body">
                            <div class="search-box">
                                <input type="text" class="search-input" placeholder="Search IRC messages..." onkeyup="searchIRC(this.value)">
                            </div>
                            {{.IRCHTML}}
                        </div>
                    </div>
                </div>

                <!-- SNMP -->
                <div id="protocol-snmp" class="protocol-content" style="display: none;">
                    <div class="card">
                        <div class="card-header">SNMP Messages</div>
                        <div class="card-body">
                            <div class="search-box">
                                <input type="text" class="search-input" placeholder="Search SNMP..." onkeyup="searchTable('snmp-table', this.value)">
                            </div>
                            {{.SNMPHTML}}
                        </div>
                    </div>
                </div>

                <!-- LDAP -->
                <div id="protocol-ldap" class="protocol-content" style="display: none;">
                    <div class="card">
                        <div class="card-header">LDAP Messages</div>
                        <div class="card-body">
                            <div class="search-box">
                                <input type="text" class="search-input" placeholder="Search LDAP..." onkeyup="searchTable('ldap-table', this.value)">
                            </div>
                            {{.LDAPHTML}}
                        </div>
                    </div>
                </div>

                <!-- SIP -->
                <div id="protocol-sip" class="protocol-content" style="display: none;">
                    <div class="card">
                        <div class="card-header">SIP Messages</div>
                        <div class="card-body">
                            <div class="search-box">
                                <input type="text" class="search-input" placeholder="Search SIP..." onkeyup="searchTable('sip-table', this.value)">
                            </div>
                            {{.SIPHTML}}
                        </div>
                    </div>
                </div>

                <!-- XMPP -->
                <div id="protocol-xmpp" class="protocol-content" style="display: none;">
                    <div class="card">
                        <div class="card-header">XMPP Messages</div>
                        <div class="card-body">
                            <div class="search-box">
                                <input type="text" class="search-input" placeholder="Search XMPP..." onkeyup="searchTable('xmpp-table', this.value)">
                            </div>
                            {{.XMPPHTML}}
                        </div>
                    </div>
                </div>

                <!-- TFTP -->
                <div id="protocol-tftp" class="protocol-content" style="display: none;">
                    <div class="card">
                        <div class="card-header">TFTP Transfers</div>
                        <div class="card-body">
                            <div class="search-box">
                                <input type="text" class="search-input" placeholder="Search TFTP..." onkeyup="searchTable('tftp-table', this.value)">
                            </div>
                            {{.TFTPHTML}}
                        </div>
                    </div>
                </div>

                <!-- Syslog -->
                <div id="protocol-syslog" class="protocol-content" style="display: none;">
                    <div class="card">
                        <div class="card-header">Syslog Messages</div>
                        <div class="card-body">
                            <div class="search-box">
                                <input type="text" class="search-input" placeholder="Search Syslog..." onkeyup="searchTable('syslog-table', this.value)">
                            </div>
                            {{.SyslogHTML}}
                        </div>
                    </div>
                </div>
            </div>

            <!-- Flows Section -->
            <div id="flows" class="content-section" style="display: none;">
                <div class="page-header">
                    <h2>Network Flows</h2>
                    <p>Top network connections and traffic patterns</p>
                </div>

                <div class="card">
                    <div class="card-header">Flow Analysis</div>
                    <div class="card-body">
                        <div class="search-box">
                            <input type="text" class="search-input" placeholder="Search flows..." onkeyup="searchTable('flows-table', this.value)">
                        </div>
                        {{.FlowsHTML}}
                    </div>
                </div>
            </div>
        </main>
    </div>

    <script>
        function showSection(sectionId) {
            // Hide all sections
            document.querySelectorAll('.content-section').forEach(section => {
                section.style.display = 'none';
            });
            
            // Show selected section
            document.getElementById(sectionId).style.display = 'block';
            
            // Update nav items
            document.querySelectorAll('.nav-item').forEach(item => {
                item.classList.remove('active');
            });
            event.target.closest('.nav-item').classList.add('active');
        }

        function searchTable(tableId, query) {
            const table = document.getElementById(tableId);
            if (!table) return;
            
            const rows = table.querySelectorAll('tbody tr');
            query = query.toLowerCase();
            
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(query) ? '' : 'none';
            });
        }

        function searchIRC(query) {
            const messages = document.querySelectorAll('.irc-message');
            query = query.toLowerCase();
            
            messages.forEach(msg => {
                const text = msg.textContent.toLowerCase();
                msg.style.display = text.includes(query) ? '' : 'none';
            });
        }

        function showIRCChannel(channel) {
            document.querySelectorAll('.irc-channel').forEach(el => el.style.display = 'none');
            document.getElementById('irc-' + channel).style.display = 'block';
            document.querySelectorAll('.irc-channel-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
        }

        function showProtocol(protocol) {
            document.querySelectorAll('.protocol-content').forEach(el => el.style.display = 'none');
            document.getElementById('protocol-' + protocol).style.display = 'block';
        }
    </script>
</body>
</html>`

// Generate HTML for beaconing patterns
func (a *Analyzer) generateBeaconingHTML() string {
	if len(a.beaconPatterns) == 0 {
		return ""
	}
	
	html := `<tr><td>` + fmt.Sprintf("%s", a.beaconPatterns[0].StartTime.Format("2006-01-02 15:04:05")) + `</td>`
	html += `<td>` + a.beaconPatterns[0].FlowKey.SrcIP + `</td>`
	html += `<td>` + a.beaconPatterns[0].FlowKey.DstIP + `</td>`
	html += `<td>` + fmt.Sprintf("%d", a.beaconPatterns[0].FlowKey.DstPort) + `</td>`
	html += `<td>` + a.beaconPatterns[0].Interval.String() + `</td>`
	html += `<td>` + fmt.Sprintf("%.3f", a.beaconPatterns[0].Jitter) + `</td>`
	html += `<td><span class="badge badge-` + a.getConfidenceBadge(a.beaconPatterns[0].Confidence) + `">` + a.beaconPatterns[0].Confidence + `</span></td>`
	html += `<td>` + fmt.Sprintf("%d", a.beaconPatterns[0].PacketCount) + `</td></tr>`
	
	for i := 1; i < len(a.beaconPatterns); i++ {
		beacon := a.beaconPatterns[i]
		html += `<tr><td>` + beacon.StartTime.Format("2006-01-02 15:04:05") + `</td>`
		html += `<td>` + beacon.FlowKey.SrcIP + `</td>`
		html += `<td>` + beacon.FlowKey.DstIP + `</td>`
		html += `<td>` + fmt.Sprintf("%d", beacon.FlowKey.DstPort) + `</td>`
		html += `<td>` + beacon.Interval.String() + `</td>`
		html += `<td>` + fmt.Sprintf("%.3f", beacon.Jitter) + `</td>`
		html += `<td><span class="badge badge-` + a.getConfidenceBadge(beacon.Confidence) + `">` + beacon.Confidence + `</span></td>`
		html += `<td>` + fmt.Sprintf("%d", beacon.PacketCount) + `</td></tr>`
	}
	
	return html
}

// Generate HTML for SSH tunnels
func (a *Analyzer) generateSSHTunnelsHTML() string {
	if len(a.sshTunnels) == 0 {
		return ""
	}
	
	html := ""
	for _, tunnel := range a.sshTunnels {
		html += `<tr><td>` + tunnel.Timestamp.Format("2006-01-02 15:04:05") + `</td>`
		html += `<td>` + tunnel.SrcIP + `</td>`
		html += `<td>` + tunnel.DstIP + `</td>`
		html += `<td>` + fmt.Sprintf("%d", tunnel.DstPort) + `</td>`
		html += `<td>` + fmt.Sprintf("%.0f KB/s", tunnel.BytesPerSecond/1024) + `</td>`
		html += `<td>` + fmt.Sprintf("%.0f", tunnel.PacketRate) + `</td>`
		html += `<td>` + fmt.Sprintf("%.0fs", tunnel.Duration) + `</td>`
		html += `<td>` + tunnel.Reason + `</td>`
		html += `<td><span class="badge badge-` + a.getConfidenceBadge(tunnel.Confidence) + `">` + tunnel.Confidence + `</span></td></tr>`
	}
	
	return html
}

// Generate HTML for ICMP tunnels
func (a *Analyzer) generateICMPTunnelsHTML() string {
	if len(a.icmpTunnels) == 0 {
		return ""
	}
	
	html := ""
	for _, tunnel := range a.icmpTunnels {
		html += `<tr><td>` + tunnel.Timestamp.Format("2006-01-02 15:04:05") + `</td>`
		html += `<td>` + tunnel.SrcIP + `</td>`
		html += `<td>` + tunnel.DstIP + `</td>`
		html += `<td>` + fmt.Sprintf("%d", tunnel.Type) + `</td>`
		html += `<td>` + fmt.Sprintf("%d", tunnel.PayloadSize) + `</td>`
		html += `<td>` + fmt.Sprintf("%.3f", tunnel.Entropy) + `</td>`
		html += `<td>` + tunnel.Reason + `</td>`
		html += `<td><span class="badge badge-` + a.getConfidenceBadge(tunnel.Confidence) + `">` + tunnel.Confidence + `</span></td></tr>`
	}
	
	return html
}

// Generate HTML for lateral movement
func (a *Analyzer) generateLateralMovementHTML() string {
	if len(a.lateralMovements) == 0 {
		return ""
	}
	
	html := ""
	for _, movement := range a.lateralMovements {
		targetSummary := ""
		if len(movement.Targets) > 3 {
			targetSummary = fmt.Sprintf("%s, %s, %s... (%d total)", 
				movement.Targets[0], movement.Targets[1], movement.Targets[2], movement.TargetCount)
		} else {
			targetSummary = strings.Join(movement.Targets, ", ")
		}
		
		html += `<tr><td>` + movement.Timestamp.Format("2006-01-02 15:04:05") + `</td>`
		html += `<td>` + movement.SrcIP + `</td>`
		html += `<td>` + fmt.Sprintf("%d", movement.TargetCount) + `</td>`
		html += `<td>` + fmt.Sprintf("%d", movement.Port) + `</td>`
		html += `<td>` + movement.Technique + `</td>`
		html += `<td>` + targetSummary + `</td>`
		html += `<td><span class="badge badge-` + a.getConfidenceBadge(movement.Confidence) + `">` + movement.Confidence + `</span></td></tr>`
	}
	
	return html
}

// Generate HTML for exfiltration
func (a *Analyzer) generateExfiltrationHTML() string {
	if len(a.exfiltrations) == 0 {
		return ""
	}
	
	html := ""
	for _, exfil := range a.exfiltrations {
		html += `<tr><td>` + exfil.Timestamp.Format("2006-01-02 15:04:05") + `</td>`
		html += `<td>` + exfil.SrcIP + `</td>`
		html += `<td>` + exfil.DstIP + `</td>`
		html += `<td>` + fmt.Sprintf("%d", exfil.DstPort) + `</td>`
		html += `<td>` + formatBytes(exfil.BytesOut) + `</td>`
		html += `<td>` + exfil.Duration.Round(time.Second).String() + `</td>`
		html += `<td>` + fmt.Sprintf("%.0f KB/s", exfil.Rate/1024) + `</td>`
		html += `<td>` + exfil.Method + `</td>`
		html += `<td><span class="badge badge-` + a.getConfidenceBadge(exfil.Confidence) + `">` + exfil.Confidence + `</span></td></tr>`
	}
	
	return html
}

// Generate HTML for TLS fingerprints
func (a *Analyzer) generateTLSFingerprintsHTML() string {
	if len(a.tlsFingerprints) == 0 {
		return ""
	}
	
	html := ""
	for _, fp := range a.tlsFingerprints {
		suspiciousIcon := ""
		if fp.Suspicious {
			suspiciousIcon = `<i class="fa fa-exclamation-triangle text-danger"></i> `
		}
		
		html += `<tr><td>` + fp.Timestamp.Format("2006-01-02 15:04:05") + `</td>`
		html += `<td>` + fp.SrcIP + `</td>`
		html += `<td>` + fp.DstIP + `</td>`
		html += `<td><code>` + fp.JA3Hash + `</code></td>`
		html += `<td>` + fp.ServerName + `</td>`
		html += `<td>` + fp.TLSVersion + `</td>`
		html += `<td>` + suspiciousIcon
		if fp.Suspicious {
			html += fp.Framework
		} else {
			html += "No"
		}
		html += `</td>`
		if fp.Suspicious {
			html += `<td><span class="badge badge-` + a.getConfidenceBadge(fp.Confidence) + `">` + fp.Confidence + `</span></td>`
		} else {
			html += `<td>-</td>`
		}
		html += `</tr>`
	}
	
	return html
}

// Generate HTML for steganography detections
func (a *Analyzer) generateStegoHTML() string {
	if len(a.stegoDetections) == 0 {
		return ""
	}
	
	html := ""
	for _, stego := range a.stegoDetections {
		html += `<tr><td>` + stego.Timestamp.Format("2006-01-02 15:04:05") + `</td>`
		html += `<td>` + stego.SrcIP + `</td>`
		html += `<td>` + stego.DstIP + `</td>`
		html += `<td>` + stego.Protocol + `</td>`
		html += `<td>` + stego.Filename + `</td>`
		html += `<td>` + stego.FileType + `</td>`
		html += `<td>` + stego.Method + `</td>`
		html += `<td>` + stego.Indicator + `</td>`
		html += `<td><span class="badge badge-` + a.getConfidenceBadge(stego.Confidence) + `">` + stego.Confidence + `</span></td></tr>`
	}
	
	return html
}

func (a *Analyzer) getConfidenceBadge(confidence string) string {
	switch strings.ToLower(confidence) {
	case "high":
		return "danger"
	case "medium":
		return "warning"
	case "low":
		return "info"
	default:
		return "secondary"
	}
}
