package analyzer

const dashboardTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PCaptor Live Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

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
            --shadow: 0 0.5rem 1rem rgba(0,0,0,0.05);
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--body-bg);
            color: var(--text-primary);
            line-height: 1.5;
        }

        .wrapper { display: flex; min-height: 100vh; }

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
        }

        .sidebar-brand h1 {
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--primary);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .live-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: var(--danger);
            color: #fff;
            font-size: 0.7rem;
            font-weight: 700;
            padding: 3px 10px;
            border-radius: 12px;
            letter-spacing: 0.5px;
            margin-top: 0.75rem;
        }

        .live-dot {
            width: 8px;
            height: 8px;
            background: #fff;
            border-radius: 50%;
            animation: pulse 1.5s ease-in-out infinite;
        }

        .live-badge.stopped { background: var(--text-secondary); }
        .live-badge.stopped .live-dot { animation: none; }

        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.4; transform: scale(0.8); }
        }

        .sidebar-nav { padding: 1rem 0; flex: 1; overflow-y: auto; }

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

        .nav-item:hover { background: var(--light); color: var(--primary); }
        .nav-item.active { background: var(--primary); color: white; border-left: 3px solid var(--primary-dark); }

        .nav-icon { font-size: 1.125rem; width: 20px; text-align: center; }

        .sidebar-footer {
            padding: 1rem 1.5rem;
            border-top: 1px solid var(--border);
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

        /* Main Content */
        .main-content { flex: 1; margin-left: 256px; padding: 2rem; }

        .page-header { margin-bottom: 2rem; }
        .page-header h2 { font-size: 1.75rem; font-weight: 700; margin-bottom: 0.25rem; }
        .page-header p { color: var(--text-secondary); font-size: 0.875rem; }

        .section { display: none; }
        .section.active { display: block; }

        /* Stat Cards */
        .card-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
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

        .card-body { padding: 1.5rem; }

        .card-header {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border);
            font-weight: 600;
            font-size: 0.875rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .stat-card { display: flex; align-items: center; justify-content: space-between; }

        .stat-label {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
            font-weight: 600;
            margin-bottom: 0.5rem;
        }

        .stat-value { font-size: 2rem; font-weight: 700; line-height: 1; }

        .stat-icon {
            width: 56px; height: 56px; border-radius: 0.5rem;
            display: flex; align-items: center; justify-content: center;
            font-size: 1.75rem; opacity: 0.9;
        }

        .stat-icon.primary { background: linear-gradient(135deg, var(--primary), var(--primary-dark)); color: white; }
        .stat-icon.success { background: linear-gradient(135deg, var(--success), #25a244); color: white; }
        .stat-icon.danger { background: linear-gradient(135deg, var(--danger), #d63939); color: white; }
        .stat-icon.warning { background: linear-gradient(135deg, var(--warning), #e09b00); color: white; }
        .stat-icon.info { background: linear-gradient(135deg, var(--info), #2d7fd6); color: white; }

        /* Protocol bars */
        .proto-bar-wrap { margin-bottom: 0.75rem; }
        .proto-bar-label {
            display: flex; justify-content: space-between;
            font-size: 0.8rem; margin-bottom: 4px; font-weight: 500;
        }
        .proto-bar {
            height: 8px; background: var(--light); border-radius: 4px; overflow: hidden;
        }
        .proto-bar-fill {
            height: 100%; border-radius: 4px; transition: width 0.4s ease;
        }

        /* Tables */
        .table-container { overflow-x: auto; }

        table {
            width: 100%; border-collapse: collapse; font-size: 0.8125rem;
        }

        thead th {
            background: var(--body-bg); padding: 0.75rem 1rem;
            text-align: left; font-weight: 600; font-size: 0.75rem;
            text-transform: uppercase; letter-spacing: 0.5px;
            color: var(--text-secondary); border-bottom: 2px solid var(--border);
        }

        tbody td {
            padding: 0.75rem 1rem; border-bottom: 1px solid var(--border);
            vertical-align: middle;
        }

        tbody tr:hover { background: #f8f9fa; }

        /* Badges */
        .badge {
            display: inline-block; padding: 0.25rem 0.75rem; border-radius: 0.25rem;
            font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;
        }

        .badge-high { background: #fde8e8; color: var(--danger); }
        .badge-medium { background: #fef3cd; color: #856404; }
        .badge-low { background: #d4edda; color: #155724; }
        .badge-protocol { background: #e8eaf6; color: var(--primary); }

        .code {
            font-family: 'SFMono-Regular', Consolas, monospace;
            font-size: 0.8rem; background: var(--light);
            padding: 2px 6px; border-radius: 3px;
        }

        /* Threat score gauge */
        .gauge-wrap { text-align: center; padding: 1rem 0; }
        .gauge-value { font-size: 3rem; font-weight: 700; }
        .gauge-label { font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.25rem; }
        .gauge-value.low { color: var(--success); }
        .gauge-value.med { color: var(--warning); }
        .gauge-value.high { color: var(--danger); }

        .empty-state {
            text-align: center; padding: 3rem; color: var(--text-secondary);
        }
        .empty-state-icon { font-size: 2.5rem; margin-bottom: 0.5rem; }

        #uptime { font-size: 0.8rem; color: var(--text-secondary); }
    </style>
</head>
<body>
<div class="wrapper">
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-brand">
            <h1>PCaptor</h1>
            <div class="live-badge" id="live-badge">
                <span class="live-dot"></span>
                <span id="live-text">LIVE CAPTURE</span>
            </div>
        </div>
        <nav class="sidebar-nav">
            <div class="nav-item active" onclick="showSection('overview')">
                <span class="nav-icon">&#128202;</span> Overview
            </div>
            <div class="nav-item" onclick="showSection('threats')">
                <span class="nav-icon">&#9888;</span> Threats
            </div>
            <div class="nav-item" onclick="showSection('flows')">
                <span class="nav-icon">&#128259;</span> Flows
            </div>
            <div class="nav-item" onclick="showSection('protocols')">
                <span class="nav-icon">&#128225;</span> Protocols
            </div>
        </nav>
        <div class="sidebar-footer">
            <div class="credit">
                <span id="uptime">Uptime: 0s</span><br>
                <a href="https://github.com/bidhata/PCaptor">PCaptor</a> by Krishnendu Paul
            </div>
        </div>
    </div>

    <!-- Main content -->
    <div class="main-content">

        <!-- Overview Section -->
        <div class="section active" id="section-overview">
            <div class="page-header">
                <h2>Live Dashboard</h2>
                <p>Real-time packet capture statistics</p>
            </div>

            <div class="card-grid">
                <div class="card"><div class="card-body stat-card">
                    <div>
                        <div class="stat-label">Packets</div>
                        <div class="stat-value" id="stat-packets">0</div>
                    </div>
                    <div class="stat-icon primary">&#128230;</div>
                </div></div>

                <div class="card"><div class="card-body stat-card">
                    <div>
                        <div class="stat-label">Bytes</div>
                        <div class="stat-value" id="stat-bytes">0</div>
                    </div>
                    <div class="stat-icon info">&#128228;</div>
                </div></div>

                <div class="card"><div class="card-body stat-card">
                    <div>
                        <div class="stat-label">Flows</div>
                        <div class="stat-value" id="stat-flows">0</div>
                    </div>
                    <div class="stat-icon success">&#128259;</div>
                </div></div>

                <div class="card"><div class="card-body stat-card">
                    <div>
                        <div class="stat-label">Threats</div>
                        <div class="stat-value" id="stat-threats">0</div>
                    </div>
                    <div class="stat-icon danger">&#9888;</div>
                </div></div>

                <div class="card"><div class="card-body stat-card">
                    <div>
                        <div class="stat-label">HTTP Requests</div>
                        <div class="stat-value" id="stat-http">0</div>
                    </div>
                    <div class="stat-icon warning">&#127760;</div>
                </div></div>

                <div class="card"><div class="card-body stat-card">
                    <div>
                        <div class="stat-label">C2 Detections</div>
                        <div class="stat-value" id="stat-c2">0</div>
                    </div>
                    <div class="stat-icon danger">&#128274;</div>
                </div></div>
            </div>

            <!-- Threat Score + Protocol distribution side by side -->
            <div style="display:grid; grid-template-columns: 1fr 2fr; gap:1.5rem; margin-bottom:2rem;">
                <div class="card">
                    <div class="card-header">Threat Score</div>
                    <div class="card-body">
                        <div class="gauge-wrap">
                            <div class="gauge-value low" id="gauge-score">0</div>
                            <div class="gauge-label">/ 100</div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-header">Protocol Distribution</div>
                    <div class="card-body" id="proto-bars">
                        <div class="empty-state">Waiting for packets...</div>
                    </div>
                </div>
            </div>

            <!-- Top Talkers -->
            <div class="card" style="margin-bottom:2rem;">
                <div class="card-header">Top Talkers</div>
                <div class="card-body">
                    <div class="table-container">
                        <table>
                            <thead><tr><th>IP</th><th>Packets</th><th>Bytes</th></tr></thead>
                            <tbody id="top-talkers-body">
                                <tr><td colspan="3" class="empty-state">Waiting for data...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- Threats Section -->
        <div class="section" id="section-threats">
            <div class="page-header">
                <h2>Threats &amp; C2 Detections</h2>
                <p>Recently detected threats (latest 20)</p>
            </div>
            <div class="card" style="margin-bottom:2rem;">
                <div class="card-header">Recent Threats</div>
                <div class="card-body">
                    <div class="table-container">
                        <table>
                            <thead><tr><th>Type</th><th>Severity</th><th>Detail</th><th>IOC</th></tr></thead>
                            <tbody id="threats-body">
                                <tr><td colspan="4" class="empty-state">No threats detected yet</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-header">C2 Detections</div>
                <div class="card-body">
                    <div class="table-container">
                        <table>
                            <thead><tr><th>Framework</th><th>Confidence</th><th>Indicator</th><th>Connection</th></tr></thead>
                            <tbody id="c2-body">
                                <tr><td colspan="4" class="empty-state">No C2 detections yet</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- Flows Section -->
        <div class="section" id="section-flows">
            <div class="page-header">
                <h2>Top Flows</h2>
                <p>Top 10 flows by bytes transferred</p>
            </div>
            <div class="card">
                <div class="card-body">
                    <div class="table-container">
                        <table>
                            <thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Bytes</th></tr></thead>
                            <tbody id="flows-body">
                                <tr><td colspan="5" class="empty-state">Waiting for flows...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- Protocols Section -->
        <div class="section" id="section-protocols">
            <div class="page-header">
                <h2>Protocol Breakdown</h2>
                <p>Full protocol distribution</p>
            </div>
            <div class="card">
                <div class="card-body">
                    <div class="table-container">
                        <table>
                            <thead><tr><th>Protocol</th><th>Packets</th><th>Share</th></tr></thead>
                            <tbody id="proto-table-body">
                                <tr><td colspan="3" class="empty-state">Waiting for packets...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

    </div>
</div>

<script>
(function() {
    // Section navigation
    window.showSection = function(id) {
        document.querySelectorAll('.section').forEach(function(s) { s.classList.remove('active'); });
        document.getElementById('section-' + id).classList.add('active');
        document.querySelectorAll('.nav-item').forEach(function(n) { n.classList.remove('active'); });
        event.currentTarget.classList.add('active');
    };

    // Formatting helpers
    function fmtNum(n) {
        if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
        if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
        return String(n);
    }

    function fmtBytes(b) {
        if (b >= 1073741824) return (b / 1073741824).toFixed(1) + ' GB';
        if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB';
        if (b >= 1024) return (b / 1024).toFixed(1) + ' KB';
        return b + ' B';
    }

    var protoColors = ['#321fdb','#2eb85c','#e55353','#f9b115','#39f','#6f42c1','#e83e8c','#20c997','#fd7e14','#6c757d'];

    function update(d) {
        // Stats
        document.getElementById('stat-packets').textContent = fmtNum(d.packets);
        document.getElementById('stat-bytes').textContent = fmtBytes(d.bytes);
        document.getElementById('stat-flows').textContent = fmtNum(d.flows);
        document.getElementById('stat-threats').textContent = String(d.threats);
        document.getElementById('stat-http').textContent = fmtNum(d.httpReqs);
        document.getElementById('stat-c2').textContent = String(d.c2Count);
        document.getElementById('uptime').textContent = 'Uptime: ' + d.uptime;

        // Threat gauge
        var gauge = document.getElementById('gauge-score');
        var score = Math.round(d.threatScore);
        gauge.textContent = score;
        gauge.className = 'gauge-value ' + (score >= 50 ? 'high' : score >= 20 ? 'med' : 'low');

        // Protocol bars
        var protos = d.protocols || {};
        var keys = Object.keys(protos).sort(function(a,b) { return protos[b] - protos[a]; });
        var maxVal = keys.length > 0 ? protos[keys[0]] : 1;
        var barHTML = '';
        keys.forEach(function(k, i) {
            var pct = Math.max(1, (protos[k] / maxVal) * 100);
            var color = protoColors[i % protoColors.length];
            barHTML += '<div class="proto-bar-wrap">' +
                '<div class="proto-bar-label"><span>' + k + '</span><span>' + fmtNum(protos[k]) + '</span></div>' +
                '<div class="proto-bar"><div class="proto-bar-fill" style="width:' + pct + '%;background:' + color + '"></div></div></div>';
        });
        document.getElementById('proto-bars').innerHTML = barHTML || '<div class="empty-state">Waiting for packets...</div>';

        // Top talkers
        var tt = d.topTalkers || [];
        var ttHTML = '';
        tt.forEach(function(t) {
            ttHTML += '<tr><td><span class="code">' + t.IP + '</span></td><td>' + fmtNum(t.Packets) + '</td><td>' + fmtBytes(t.Bytes) + '</td></tr>';
        });
        document.getElementById('top-talkers-body').innerHTML = ttHTML || '<tr><td colspan="3" class="empty-state">Waiting for data...</td></tr>';

        // Recent threats
        var thr = d.recentThreats || [];
        var thrHTML = '';
        thr.forEach(function(t) {
            var cls = t.Severity === 'high' ? 'badge-high' : t.Severity === 'medium' ? 'badge-medium' : 'badge-low';
            thrHTML += '<tr><td><strong>' + t.Type + '</strong></td>' +
                '<td><span class="badge ' + cls + '">' + t.Severity.toUpperCase() + '</span></td>' +
                '<td>' + t.Detail + '</td><td><span class="code">' + t.IOC + '</span></td></tr>';
        });
        document.getElementById('threats-body').innerHTML = thrHTML || '<tr><td colspan="4" class="empty-state">No threats detected yet</td></tr>';

        // C2 detections
        var c2 = d.recentC2 || [];
        var c2HTML = '';
        c2.forEach(function(c) {
            var cls = c.Confidence === 'high' ? 'badge-high' : c.Confidence === 'medium' ? 'badge-medium' : 'badge-low';
            c2HTML += '<tr><td><strong>' + c.Framework + '</strong></td>' +
                '<td><span class="badge ' + cls + '">' + c.Confidence.toUpperCase() + '</span></td>' +
                '<td>' + c.Indicator + '</td><td><span class="code">' + c.SrcIP + ' &rarr; ' + c.DstIP + '</span></td></tr>';
        });
        document.getElementById('c2-body').innerHTML = c2HTML || '<tr><td colspan="4" class="empty-state">No C2 detections yet</td></tr>';

        // Top flows
        var fl = d.topFlows || [];
        var flHTML = '';
        fl.forEach(function(f) {
            flHTML += '<tr><td><span class="code">' + f.srcIP + ':' + f.srcPort + '</span></td>' +
                '<td><span class="code">' + f.dstIP + ':' + f.dstPort + '</span></td>' +
                '<td><span class="badge badge-protocol">' + f.proto + '</span></td>' +
                '<td>' + fmtNum(f.packets) + '</td><td>' + fmtBytes(f.bytes) + '</td></tr>';
        });
        document.getElementById('flows-body').innerHTML = flHTML || '<tr><td colspan="5" class="empty-state">Waiting for flows...</td></tr>';

        // Protocols table
        var ptHTML = '';
        var totalPkts = 0;
        keys.forEach(function(k) { totalPkts += protos[k]; });
        keys.forEach(function(k) {
            var share = totalPkts > 0 ? ((protos[k] / totalPkts) * 100).toFixed(1) + '%' : '0%';
            ptHTML += '<tr><td><span class="badge badge-protocol">' + k + '</span></td><td>' + fmtNum(protos[k]) + '</td><td>' + share + '</td></tr>';
        });
        document.getElementById('proto-table-body').innerHTML = ptHTML || '<tr><td colspan="3" class="empty-state">Waiting for packets...</td></tr>';

        // Stopped state
        if (d.stopped) {
            var badge = document.getElementById('live-badge');
            badge.classList.add('stopped');
            document.getElementById('live-text').textContent = 'CAPTURE ENDED';
        }
    }

    // Initial fetch
    fetch('/api/snapshot')
        .then(function(r) { return r.json(); })
        .then(update)
        .catch(function() {});

    // SSE stream
    var es = new EventSource('/api/stream');
    es.onmessage = function(e) {
        try { update(JSON.parse(e.data)); } catch(err) {}
    };
    es.addEventListener('done', function() {
        es.close();
    });
    es.onerror = function() {
        // EventSource auto-reconnects; if server is gone, it will stop after a few retries.
    };
})();
</script>
</body>
</html>`
