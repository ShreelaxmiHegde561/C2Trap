"""
C2Trap Security Report Generator
Generates professional HTML reports with zero external dependencies.
"""

from datetime import datetime
import os
import json


def generate_report(stats: dict, recent_alerts: list, output_path: str):
    """Generate a comprehensive HTML security report."""

    total = stats.get('total_events', 0)
    critical = stats.get('critical_alerts', 0)
    high = stats.get('high_severity', 0)
    techniques = stats.get('mitre_techniques', [])
    sources = stats.get('sources', [])

    # Determine threat level
    if critical > 0 or high > 5:
        threat_level = "CRITICAL"
        threat_color = "#e74c3c"
        threat_desc = "Multiple high-severity indicators detected. Immediate action required."
    elif high > 0 or len(recent_alerts) > 0:
        threat_level = "ELEVATED"
        threat_color = "#e67e22"
        threat_desc = "Suspicious activities detected. Investigation recommended."
    else:
        threat_level = "NORMAL"
        threat_color = "#27ae60"
        threat_desc = "System operating within normal parameters."

    # Group alerts by type
    dga_alerts = [a for a in recent_alerts if 'dga' in str(a).lower() or 'T1568' in str(a)]
    tunnel_alerts = [a for a in recent_alerts if 'tunnel' in str(a).lower() or 'T1071.004' in str(a)]
    beacon_alerts = [a for a in recent_alerts if 'beacon' in str(a).lower() or 'T1071.001' in str(a)]
    tls_alerts = [a for a in recent_alerts if 'tls' in str(a).lower() or 'T1573' in str(a)]
    exfil_alerts = [a for a in recent_alerts if 'exfil' in str(a).lower() or 'T1048' in str(a)]
    other_alerts = [a for a in recent_alerts if a not in dga_alerts + tunnel_alerts + beacon_alerts + tls_alerts + exfil_alerts]

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Build alert sections
    alert_sections = ""

    if dga_alerts:
        rows = ""
        for a in dga_alerts[:5]:
            d = a.get('raw_data', a.get('details', {}))
            rows += f"""<tr>
                <td>{d.get('domain', d.get('query_name', 'N/A'))}</td>
                <td>{d.get('dga_score', d.get('score', 'N/A'))}</td>
                <td>{d.get('entropy', 'N/A')}</td>
                <td><span class="badge critical">DGA</span></td>
            </tr>"""
        alert_sections += f"""
        <div class="section">
            <h2>🔴 Domain Generation Algorithm (DGA) — T1568.002</h2>
            <p>Algorithmically generated domains detected. Malware uses DGA to dynamically generate C2 server addresses, making blocking difficult.</p>
            <table><tr><th>Domain</th><th>Score</th><th>Entropy</th><th>Verdict</th></tr>{rows}</table>
            <div class="recommendation">
                <strong>⚡ Action Required:</strong> Block these domains at your DNS resolver and firewall. Investigate the source host for malware infection.
            </div>
        </div>"""

    if tunnel_alerts:
        rows = ""
        for a in tunnel_alerts[:5]:
            d = a.get('raw_data', a.get('details', {}))
            rows += f"""<tr>
                <td style="word-break:break-all;max-width:300px">{d.get('domain', d.get('query_name', 'N/A'))}</td>
                <td>{d.get('encoding', 'N/A')}</td>
                <td>{d.get('tunnel_score', d.get('score', 'N/A'))}</td>
                <td><span class="badge critical">TUNNEL</span></td>
            </tr>"""
        alert_sections += f"""
        <div class="section">
            <h2>🟠 DNS Tunneling Detected — T1071.004</h2>
            <p>Data exfiltration via DNS subdomains detected. Attackers encode stolen data (Base64/Hex) into DNS queries to bypass firewalls.</p>
            <table><tr><th>Query</th><th>Encoding</th><th>Score</th><th>Verdict</th></tr>{rows}</table>
            <div class="recommendation">
                <strong>⚡ Action Required:</strong> Block the parent domain. Monitor for large volumes of DNS TXT record queries. Check endpoint for data theft.
            </div>
        </div>"""

    if beacon_alerts:
        rows = ""
        for a in beacon_alerts[:5]:
            d = a.get('raw_data', a.get('details', {}))
            src = d.get('src_ip', d.get('remote_ip', 'N/A'))
            dst = d.get('dst_ip', 'N/A')
            rows += f"""<tr>
                <td>{src}</td><td>{dst}</td>
                <td>{d.get('interval', 'N/A')}s</td>
                <td>{d.get('jitter_percent', d.get('jitter', 'N/A'))}%</td>
                <td><span class="badge critical">C2</span></td>
            </tr>"""
        alert_sections += f"""
        <div class="section">
            <h2>🔴 C2 Beaconing Detected — T1071.001</h2>
            <p>Periodic callback patterns found using FFT (Fast Fourier Transform) analysis. An infected host is communicating with a C2 server at regular intervals.</p>
            <table><tr><th>Source</th><th>C2 Server</th><th>Interval</th><th>Jitter</th><th>Verdict</th></tr>{rows}</table>
            <div class="recommendation">
                <strong>⚡ Action Required:</strong> Immediately isolate the source IP. Block the C2 destination. Run EDR/AV scan on the infected host.
            </div>
        </div>"""

    if tls_alerts:
        rows = ""
        for a in tls_alerts[:5]:
            d = a.get('raw_data', a.get('details', {}))
            rows += f"""<tr>
                <td>{d.get('ja3_hash', d.get('ja3', 'N/A'))[:20]}...</td>
                <td>{d.get('dst_ip', d.get('server_ip', 'N/A'))}</td>
                <td>{', '.join(d.get('alerts', d.get('anomalies', ['N/A'])))[:80]}</td>
                <td><span class="badge high">SUSPICIOUS</span></td>
            </tr>"""
        alert_sections += f"""
        <div class="section">
            <h2>🟡 TLS/SSL Anomalies — T1573</h2>
            <p>Suspicious TLS parameters detected matching known C2 tool fingerprints (Cobalt Strike, Metasploit).</p>
            <table><tr><th>JA3 Hash</th><th>Server</th><th>Anomalies</th><th>Verdict</th></tr>{rows}</table>
            <div class="recommendation">
                <strong>⚡ Action Required:</strong> Block traffic to IPs with known malicious JA3 fingerprints. Inspect certificates for self-signed or short-lived certs.
            </div>
        </div>"""

    if exfil_alerts:
        rows = ""
        for a in exfil_alerts[:5]:
            d = a.get('raw_data', a.get('details', {}))
            rows += f"""<tr>
                <td>{d.get('remote_ip', 'N/A')}</td>
                <td>{d.get('endpoint', d.get('path', 'N/A'))}</td>
                <td>{d.get('size', 'N/A')} bytes</td>
                <td><span class="badge high">EXFIL</span></td>
            </tr>"""
        alert_sections += f"""
        <div class="section">
            <h2>🟠 Data Exfiltration Attempt — T1048</h2>
            <p>Suspicious outbound data transfers detected.</p>
            <table><tr><th>Destination</th><th>Endpoint</th><th>Size</th><th>Verdict</th></tr>{rows}</table>
            <div class="recommendation">
                <strong>⚡ Action Required:</strong> Investigate the destination IP. Check for sensitive data exposure.
            </div>
        </div>"""

    if other_alerts:
        rows = ""
        for a in other_alerts[:10]:
            d = a.get('raw_data', a.get('details', {}))
            rows += f"""<tr>
                <td>{a.get('title', a.get('event_type', 'Unknown'))}</td>
                <td>{a.get('severity', 'medium')}</td>
                <td>{d.get('remote_ip', d.get('src_ip', 'N/A'))}</td>
                <td>{a.get('description', 'N/A')[:80]}</td>
            </tr>"""
        alert_sections += f"""
        <div class="section">
            <h2>📋 Other Alerts</h2>
            <table><tr><th>Type</th><th>Severity</th><th>Source</th><th>Details</th></tr>{rows}</table>
        </div>"""

    if not alert_sections:
        alert_sections = '<div class="section"><h2>✅ No Significant Threats</h2><p>No high-severity alerts detected in the reporting period. Continue routine monitoring.</p></div>'

    # MITRE section
    mitre_rows = ""
    technique_names = {
        'T1568': 'Dynamic Resolution (DGA)', 'T1568.002': 'DGA Domains',
        'T1071': 'Application Layer Protocol', 'T1071.001': 'Web Protocols (Beacon)',
        'T1071.004': 'DNS Tunneling', 'T1573': 'Encrypted Channel (TLS)',
        'T1048': 'Exfiltration Over IP', 'T1041': 'Exfil Over C2',
        'T1105': 'Ingress Tool Transfer', 'T1059': 'Command Scripting',
        'T1190': 'Exploit Public App', 'T1078': 'Valid Accounts',
        'T1082': 'System Discovery', 'T1046': 'Network Scanning',
        'T1027': 'Obfuscated Files', 'T1021': 'Remote Services',
    }
    if isinstance(techniques, list):
        for t in techniques:
            name = technique_names.get(t, 'Unknown')
            mitre_rows += f'<tr><td><code>{t}</code></td><td>{name}</td><td><span class="badge high">DETECTED</span></td></tr>'
    elif isinstance(techniques, dict):
        for t, count in techniques.items():
            name = technique_names.get(t, 'Unknown')
            mitre_rows += f'<tr><td><code>{t}</code></td><td>{name}</td><td>{count}x</td></tr>'

    # Source summary
    source_names = {
        'http_decoy': '⛔ HTTP Decoy (Rerouted)',
        'dns_decoy': '🌀 DNS Sinkhole',
        'ftp_decoy': '🔒 FTP Honeypot',
        'beacon_detector': '🚨 Beacon Detector',
        'packet_capture': '📡 Packet Capture',
        'sandbox': '🔬 Sandbox',
        'ja3_generator': '🔑 JA3 Fingerprint',
        'dns_spoof': '🌀 DNS Spoof',
    }
    source_list = ""
    for s in sources:
        label = source_names.get(s, s)
        source_list += f"<li>{label}</li>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>C2Trap Security Report — {timestamp}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #1a1a2e; color: #eee; padding: 40px; }}
    .container {{ max-width: 900px; margin: 0 auto; }}
    .header {{ text-align: center; margin-bottom: 40px; padding: 30px; background: linear-gradient(135deg, #0f3460, #16213e); border-radius: 12px; border: 1px solid #e94560; }}
    .header h1 {{ font-size: 28px; color: #e94560; margin-bottom: 8px; }}
    .header .subtitle {{ color: #888; font-size: 14px; }}
    .threat-level {{ display: inline-block; padding: 8px 24px; border-radius: 20px; font-weight: bold; font-size: 18px; margin: 15px 0; background: {threat_color}22; color: {threat_color}; border: 2px solid {threat_color}; }}
    .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 25px 0; }}
    .stat-card {{ background: #16213e; padding: 20px; border-radius: 10px; text-align: center; border: 1px solid #333; }}
    .stat-card .value {{ font-size: 32px; font-weight: bold; color: #e94560; }}
    .stat-card .label {{ font-size: 12px; color: #888; margin-top: 5px; text-transform: uppercase; }}
    .section {{ background: #16213e; border-radius: 10px; padding: 25px; margin: 20px 0; border: 1px solid #333; }}
    .section h2 {{ color: #e94560; margin-bottom: 15px; font-size: 20px; }}
    .section p {{ color: #aaa; margin-bottom: 15px; line-height: 1.6; }}
    table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
    th {{ background: #0f3460; padding: 10px 12px; text-align: left; font-size: 12px; text-transform: uppercase; color: #888; }}
    td {{ padding: 10px 12px; border-bottom: 1px solid #2a2a4a; font-size: 13px; }}
    tr:hover {{ background: #1a1a3e; }}
    .badge {{ padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: bold; }}
    .badge.critical {{ background: #e74c3c33; color: #e74c3c; }}
    .badge.high {{ background: #e67e2233; color: #e67e22; }}
    .badge.medium {{ background: #f1c40f33; color: #f1c40f; }}
    .recommendation {{ background: #e74c3c15; border-left: 4px solid #e74c3c; padding: 15px; margin-top: 15px; border-radius: 0 8px 8px 0; }}
    .footer {{ text-align: center; margin-top: 40px; padding: 20px; color: #555; font-size: 12px; }}
    @media print {{ body {{ background: #fff; color: #000; }} .section {{ border: 1px solid #ccc; }} th {{ background: #eee; color: #333; }} }}
</style>
</head>
<body>
<div class="container">

<div class="header">
    <h1>C2Trap Security Incident Report</h1>
    <div class="subtitle">Generated: {timestamp} | Automated Threat Analysis</div>
    <div class="threat-level">{threat_level} THREAT LEVEL</div>
    <p style="color: #aaa; margin-top: 10px;">{threat_desc}</p>
</div>

<div class="stats-grid">
    <div class="stat-card"><div class="value">{total}</div><div class="label">Total Events</div></div>
    <div class="stat-card"><div class="value">{len(recent_alerts)}</div><div class="label">Alerts</div></div>
    <div class="stat-card"><div class="value">{critical}</div><div class="label">Critical</div></div>
    <div class="stat-card"><div class="value">{len(techniques) if isinstance(techniques, (list, dict)) else 0}</div><div class="label">MITRE Techniques</div></div>
</div>

{alert_sections}

<div class="section">
    <h2>📊 MITRE ATT&CK Coverage</h2>
    {"<table><tr><th>Technique</th><th>Name</th><th>Status</th></tr>" + mitre_rows + "</table>" if mitre_rows else "<p>No MITRE techniques mapped in this period.</p>"}
</div>

<div class="section">
    <h2>📡 Active Detection Sources</h2>
    <p>Traffic was captured and analyzed from the following sources:</p>
    <ul style="list-style: none; padding: 0;">{source_list}</ul>
</div>

<div class="footer">
    <p>C2Trap Automated Security Report — Confidential</p>
    <p>This report was generated automatically by the C2Trap threat detection system.</p>
    <p style="margin-top: 10px;">💡 Tip: Use Ctrl+P to save this report as PDF from your browser.</p>
</div>

</div>
</body>
</html>"""

    with open(output_path, 'w') as f:
        f.write(html)
    return output_path
