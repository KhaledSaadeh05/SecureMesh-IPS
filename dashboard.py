"""
dashboard.py -- SecureMesh IPS v3 OOP Edition (Slim)
Flask web dashboard. Imports from ips_core.py.
"""

from flask import Flask, render_template_string, request, session, redirect, url_for, jsonify
from datetime import datetime
import sqlite3

from ips_core import IPDatabase, PacketAnalyzer


class Dashboard:
    """
    Flask web dashboard with 4 pages + 2 live JSON endpoints.

    ENCAPSULATION: Flask app, credentials, DB path all private.
    COMPOSITION:   has-a PacketAnalyzer and IPDatabase.
    """

    _LOGIN_TEMPLATE = """<!DOCTYPE html>
<html><head><title>SecureMesh IPS Login</title></head>
<body style="font-family:Arial;background:#111;color:#eee;display:flex;
justify-content:center;align-items:center;height:100vh;margin:0">
<div style="background:#1b1b1b;padding:40px;border-radius:10px;min-width:320px;">
  <h2 style="margin:0 0 24px 0;text-align:center;color:#9bd;">SecureMesh IPS v3</h2>
  {% if error %}<p style="color:#f66;text-align:center;margin:0 0 16px 0;">{{ error }}</p>{% endif %}
  <form method="post">
    <input name="username" placeholder="Username" autocomplete="off"
           style="width:100%;padding:10px;margin:8px 0;background:#222;border:1px solid
           #444;color:#eee;border-radius:4px;box-sizing:border-box;font-size:14px;"><br>
    <input name="password" type="password" placeholder="Password"
           style="width:100%;padding:10px;margin:8px 0;background:#222;border:1px solid
           #444;color:#eee;border-radius:4px;box-sizing:border-box;font-size:14px;"><br>
    <button type="submit"
            style="width:100%;padding:11px;margin-top:12px;background:#2a6ebb;
            color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:15px;">
      Login
    </button>
  </form>
</div></body></html>"""

    _HOME_TEMPLATE = """<!DOCTYPE html>
<html><head><title>SecureMesh IPS v3</title></head>
<body style="font-family:Arial;background:#111;color:#eee;padding:20px;">
  <h1 style="color:#9bd;">SecureMesh IPS v3
    <span id="live-dot" style="display:inline-block;width:10px;height:10px;
      border-radius:50%;background:#2f2;margin-left:10px;vertical-align:middle;
      box-shadow:0 0 6px #2f2;" title="Live"></span>
    <span style="font-size:13px;color:#555;margin-left:6px;">LIVE</span>
  </h1>
  <div style="margin:10px 0 20px 0;">
    <a href="/" style="color:#9bd;text-decoration:none;margin-right:15px;">Home</a>
    <a href="/blacklist" style="color:#f88;text-decoration:none;margin-right:15px;">Blacklist</a>
    <a href="/whitelist" style="color:#8f8;text-decoration:none;margin-right:15px;">Whitelist</a>
    <a href="/alerts" style="color:#fa0;text-decoration:none;margin-right:15px;">Alerts</a>
    <a href="/logout" style="color:#aaa;text-decoration:none;float:right;">Logout</a>
  </div>
  <div style="display:flex;gap:16px;flex-wrap:wrap;">
    <div style="flex:1;min-width:160px;background:#1b1b1b;padding:14px;border-radius:10px;border-left:4px solid #f88;">
      <div style="color:#f88;font-size:13px;margin-bottom:6px;">Blacklisted IPs</div>
      <div id="stat-blacklist" style="font-size:36px;font-weight:bold;">{{ stats.blacklist }}</div>
    </div>
    <div style="flex:1;min-width:160px;background:#1b1b1b;padding:14px;border-radius:10px;border-left:4px solid #8f8;">
      <div style="color:#8f8;font-size:13px;margin-bottom:6px;">Whitelisted IPs</div>
      <div id="stat-whitelist" style="font-size:36px;font-weight:bold;">{{ stats.whitelist }}</div>
    </div>
    <div style="flex:1;min-width:160px;background:#1b1b1b;padding:14px;border-radius:10px;border-left:4px solid #9bd;">
      <div style="color:#9bd;font-size:13px;margin-bottom:6px;">Total IPs Tracked</div>
      <div id="stat-total-ips" style="font-size:36px;font-weight:bold;">{{ stats.total }}</div>
    </div>
    <div style="flex:1;min-width:160px;background:#1b1b1b;padding:14px;border-radius:10px;border-left:4px solid #fa0;">
      <div style="color:#fa0;font-size:13px;margin-bottom:6px;">Total Alerts</div>
      <div id="stat-alerts" style="font-size:36px;font-weight:bold;">{{ alert_count }}</div>
    </div>
    <div style="flex:1;min-width:160px;background:#1b1b1b;padding:14px;border-radius:10px;border-left:4px solid #6af;">
      <div style="color:#6af;font-size:13px;margin-bottom:6px;">Packets Sniffed ({{ iface }})</div>
      <div id="stat-pkt-total" style="font-size:36px;font-weight:bold;">{{ pkt_stats.total }}</div>
    </div>
    <div style="flex:1;min-width:160px;background:#1b1b1b;padding:14px;border-radius:10px;border-left:4px solid #f44;">
      <div style="color:#f44;font-size:13px;margin-bottom:6px;">Packets Blocked + RST</div>
      <div id="stat-pkt-blocked" style="font-size:36px;font-weight:bold;">{{ pkt_stats.blocked }}</div>
    </div>
  </div>
  <h2>Recent Alerts (live)</h2>
  <div id="recent-alerts">
    {% if recent %}
      {% for a in recent %}
        <div style="background:#1b1b1b;padding:10px 14px;border-left:4px solid #f44;border-radius:6px;margin-bottom:6px;">
          <span style="color:#777;font-size:12px;">{{ a.ts }}</span>
          <span style="color:#f88;font-family:monospace;margin:0 12px;">{{ a.src_ip }}</span>
          <span style="color:#fa0;">{{ a.detection }}</span>
          <span style="color:#6af;margin-left:12px;font-size:13px;">{{ a.action }}</span>
        </div>
      {% endfor %}
    {% else %}
      <p style="color:#555;">No alerts yet.</p>
    {% endif %}
  </div>
  <p style="font-size:12px;color:#444;margin-top:24px;">Last update: <span id="last-refresh">{{ now }}</span></p>
  <script>
    function fmt(a) {
      return '<div style="background:#1b1b1b;padding:10px 14px;border-left:4px solid #f44;border-radius:6px;margin-bottom:6px;">' +
             '<span style="color:#777;font-size:12px;">'+(a.ts||'')+'</span>' +
             '<span style="color:#f88;font-family:monospace;margin:0 12px;">'+(a.src_ip||'')+'</span>' +
             '<span style="color:#fa0;">'+(a.detection||'')+'</span>' +
             '<span style="color:#6af;margin-left:12px;font-size:13px;">'+(a.action||'')+'</span></div>';
    }
    function poll() {
      fetch('/api/live').then(r=>r.json()).then(d=>{
        document.getElementById('stat-blacklist').textContent   = d.blacklist    || 0;
        document.getElementById('stat-whitelist').textContent   = d.whitelist    || 0;
        document.getElementById('stat-total-ips').textContent   = d.total_ips    || 0;
        document.getElementById('stat-alerts').textContent      = d.alert_count  || 0;
        document.getElementById('stat-pkt-total').textContent   = d.total_packets  || 0;
        document.getElementById('stat-pkt-blocked').textContent = d.blocked_packets || 0;
        var box = document.getElementById('recent-alerts');
        if (d.recent && d.recent.length) { box.innerHTML = d.recent.map(fmt).join(''); }
        document.getElementById('last-refresh').textContent = d.now || '';
      }).catch(function(){});
    }
    setInterval(poll, 3000);
  </script>
</body></html>"""

    _LIST_TEMPLATE = """<!DOCTYPE html>
<html><head><title>{{ title }} - SecureMesh IPS v3</title></head>
<body style="font-family:Arial;background:#111;color:#eee;padding:20px;">
  <h1 style="color:{{ heading_color }};">{{ title }}</h1>
  <div style="margin:10px 0 20px 0;">
    <a href="/" style="color:#9bd;text-decoration:none;margin-right:15px;">Home</a>
    <a href="/blacklist" style="color:#f88;text-decoration:none;margin-right:15px;">Blacklist</a>
    <a href="/whitelist" style="color:#8f8;text-decoration:none;margin-right:15px;">Whitelist</a>
    <a href="/alerts" style="color:#fa0;text-decoration:none;margin-right:15px;">Alerts</a>
    <a href="/logout" style="color:#aaa;text-decoration:none;float:right;">Logout</a>
  </div>
  <p style="color:#777;">Showing {{ rows|length }} IP(s)</p>
  {% if rows %}
  <table style="width:100%;border-collapse:collapse;">
    <tr style="background:#222;border-bottom:2px solid #333;">
      <th style="padding:10px 12px;text-align:left;color:#aaa;font-weight:normal;">IP Address</th>
      <th style="padding:10px 12px;text-align:left;color:#aaa;font-weight:normal;">Status</th>
      <th style="padding:10px 12px;text-align:left;color:#aaa;font-weight:normal;">First Seen</th>
      <th style="padding:10px 12px;text-align:left;color:#aaa;font-weight:normal;">Last Seen</th>
      <th style="padding:10px 12px;text-align:left;color:#aaa;font-weight:normal;">Hits</th>
      <th style="padding:10px 12px;text-align:left;color:#aaa;font-weight:normal;">Source</th>
    </tr>
    {% for row in rows %}
    <tr style="border-bottom:1px solid #1e1e1e;background:{% if loop.index is odd %}#181818{% else %}#141414{% endif %};">
      <td style="padding:8px 12px;font-family:monospace;font-size:14px;">{{ row.ip }}</td>
      <td style="padding:8px 12px;color:{% if row.status == 'blacklist' %}#f88{% else %}#8f8{% endif %};">{{ row.status }}</td>
      <td style="padding:8px 12px;color:#666;font-size:13px;">{{ row.first_seen }}</td>
      <td style="padding:8px 12px;color:#666;font-size:13px;">{{ row.last_seen }}</td>
      <td style="padding:8px 12px;font-weight:bold;">{{ row.hit_count }}</td>
      <td style="padding:8px 12px;color:#888;font-size:13px;">{{ row.source }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}<p style="color:#555;">No IPs in this list yet.</p>{% endif %}
</body></html>"""

    _ALERTS_TEMPLATE = """<!DOCTYPE html>
<html><head><title>Alerts - SecureMesh IPS v3</title></head>
<body style="font-family:Arial;background:#111;color:#eee;padding:20px;">
  <h1 style="color:#fa0;">Alerts Database
    <span id="live-dot" style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#2f2;margin-left:10px;vertical-align:middle;box-shadow:0 0 6px #2f2;"></span>
  </h1>
  <div style="margin:10px 0 20px 0;">
    <a href="/" style="color:#9bd;text-decoration:none;margin-right:15px;">Home</a>
    <a href="/blacklist" style="color:#f88;text-decoration:none;margin-right:15px;">Blacklist</a>
    <a href="/whitelist" style="color:#8f8;text-decoration:none;margin-right:15px;">Whitelist</a>
    <a href="/alerts" style="color:#fa0;text-decoration:none;margin-right:15px;">Alerts</a>
    <a href="/logout" style="color:#aaa;text-decoration:none;float:right;">Logout</a>
  </div>
  <p style="color:#777;">Last <span id="alert-count">{{ rows|length }}</span> alert(s) | Last update: <span id="last-refresh">--</span></p>
  <div id="alerts-table">
    {% if rows %}
    <table style="width:100%;border-collapse:collapse;">
      <tr style="background:#222;border-bottom:2px solid #333;">
        <th style="padding:10px 12px;text-align:left;color:#aaa;font-weight:normal;">Time</th>
        <th style="padding:10px 12px;text-align:left;color:#aaa;font-weight:normal;">Source IP</th>
        <th style="padding:10px 12px;text-align:left;color:#aaa;font-weight:normal;">Dest IP</th>
        <th style="padding:10px 12px;text-align:left;color:#aaa;font-weight:normal;">Port</th>
        <th style="padding:10px 12px;text-align:left;color:#aaa;font-weight:normal;">Detection</th>
        <th style="padding:10px 12px;text-align:left;color:#aaa;font-weight:normal;">Action</th>
        <th style="padding:10px 12px;text-align:left;color:#aaa;font-weight:normal;">Score</th>
      </tr>
      {% for row in rows %}
      <tr style="border-bottom:1px solid #1e1e1e;background:{% if loop.index is odd %}#181818{% else %}#141414{% endif %};">
        <td style="padding:8px 12px;color:#666;font-size:12px;">{{ row.ts }}</td>
        <td style="padding:8px 12px;font-family:monospace;color:#f88;">{{ row.src_ip }}</td>
        <td style="padding:8px 12px;font-family:monospace;color:#999;">{{ row.dst_ip }}</td>
        <td style="padding:8px 12px;color:#999;">{{ row.port }}</td>
        <td style="padding:8px 12px;color:#fa0;font-size:13px;">{{ row.detection }}</td>
        <td style="padding:8px 12px;color:#6af;font-size:13px;">{{ row.action }}</td>
        <td style="padding:8px 12px;font-weight:bold;">{{ row.score }}</td>
      </tr>
      {% endfor %}
    </table>
    {% else %}<p style="color:#555;">No alerts yet.</p>{% endif %}
  </div>
  <script>
    function renderRows(rows) {
      if (!rows||!rows.length) return '<p style="color:#555;">No alerts yet.</p>';
      var h='<table style="width:100%;border-collapse:collapse;"><tr style="background:#222;border-bottom:2px solid #333;">' +
        '<th style="padding:10px 12px;text-align:left;color:#aaa;font-weight:normal;">Time</th>' +
        '<th style="padding:10px 12px;text-align:left;color:#aaa;font-weight:normal;">Source IP</th>' +
        '<th style="padding:10px 12px;text-align:left;color:#aaa;font-weight:normal;">Dest IP</th>' +
        '<th style="padding:10px 12px;text-align:left;color:#aaa;font-weight:normal;">Port</th>' +
        '<th style="padding:10px 12px;text-align:left;color:#aaa;font-weight:normal;">Detection</th>' +
        '<th style="padding:10px 12px;text-align:left;color:#aaa;font-weight:normal;">Action</th>' +
        '<th style="padding:10px 12px;text-align:left;color:#aaa;font-weight:normal;">Score</th></tr>';
      var b=rows.map(function(r,i){
        var bg=(i%2===0)?'#181818':'#141414';
        return '<tr style="border-bottom:1px solid #1e1e1e;background:'+bg+';">' +
          '<td style="padding:8px 12px;color:#666;font-size:12px;">'+(r.ts||'')+'</td>' +
          '<td style="padding:8px 12px;font-family:monospace;color:#f88;">'+(r.src_ip||'')+'</td>' +
          '<td style="padding:8px 12px;font-family:monospace;color:#999;">'+(r.dst_ip||'')+'</td>' +
          '<td style="padding:8px 12px;color:#999;">'+(r.port||'')+'</td>' +
          '<td style="padding:8px 12px;color:#fa0;font-size:13px;">'+(r.detection||'')+'</td>' +
          '<td style="padding:8px 12px;color:#6af;font-size:13px;">'+(r.action||'')+'</td>' +
          '<td style="padding:8px 12px;font-weight:bold;">'+(r.score||'')+'</td></tr>';
      }).join('');
      return h+b+'</table>';
    }
    function pollAlerts() {
      fetch('/api/live').then(r=>r.json()).then(d=>{
        return fetch('/api/alerts').then(r2=>r2.json()).then(d2=>{
          document.getElementById('alerts-table').innerHTML = renderRows(d2.rows);
          document.getElementById('alert-count').textContent = d2.rows?d2.rows.length:0;
          document.getElementById('last-refresh').textContent = d.now||'';
        });
      }).catch(function(){});
    }
    setInterval(pollAlerts, 3000);
  </script>
</body></html>"""

    def __init__(self, analyzer: PacketAnalyzer, ip_db: IPDatabase,
                 db_file="alerts.db", host="127.0.0.1", port=5000,
                 username="admin", password="securemesh", iface="eth0"):
        # ENCAPSULATION: all private
        self._analyzer = analyzer
        self._ip_db    = ip_db
        self._db_file  = db_file
        self._host     = host
        self._port     = port
        self._username = username
        self._password = password
        self._iface    = iface
        self._app      = Flask(__name__)
        self._app.secret_key = "securemesh-ips-v3-secret"
        self._register_routes()

    def _is_logged_in(self):
        return session.get("logged_in") is True

    def _get_alerts(self, limit=200):
        try:
            con = sqlite3.connect(self._db_file, timeout=5)
            con.row_factory = sqlite3.Row
            rows = con.execute(
                "SELECT ts,src_ip,dst_ip,port,detection,action,score "
                "FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            con.close()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def _get_alert_count(self):
        try:
            con   = sqlite3.connect(self._db_file, timeout=5)
            count = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            con.close()
            return count
        except Exception:
            return 0

    def _register_routes(self):
        app = self._app

        @app.route("/login", methods=["GET", "POST"])
        def login():
            error = None
            if request.method == "POST":
                if (request.form.get("username") == self._username and
                        request.form.get("password") == self._password):
                    session["logged_in"] = True
                    return redirect(url_for("home"))
                error = "Invalid username or password."
            return render_template_string(self._LOGIN_TEMPLATE, error=error)

        @app.route("/logout")
        def logout():
            session.clear()
            return redirect(url_for("login"))

        @app.route("/")
        def home():
            if not self._is_logged_in():
                return redirect(url_for("login"))
            return render_template_string(
                self._HOME_TEMPLATE,
                stats=self._ip_db.get_stats(),
                pkt_stats=self._analyzer.get_packet_stats(),
                recent=self._get_alerts(limit=10),
                alert_count=self._get_alert_count(),
                now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                iface=self._iface,
            )

        @app.route("/blacklist")
        def blacklist():
            if not self._is_logged_in():
                return redirect(url_for("login"))
            df   = self._ip_db.get_blacklist(limit=200)
            rows = df.to_dict(orient="records") if not df.empty else []
            return render_template_string(
                self._LIST_TEMPLATE, title="Blacklisted IPs",
                heading_color="#f88", rows=rows)

        @app.route("/whitelist")
        def whitelist():
            if not self._is_logged_in():
                return redirect(url_for("login"))
            df   = self._ip_db.get_whitelist(limit=200)
            rows = df.to_dict(orient="records") if not df.empty else []
            return render_template_string(
                self._LIST_TEMPLATE, title="Whitelisted IPs",
                heading_color="#8f8", rows=rows)

        @app.route("/alerts")
        def alerts():
            if not self._is_logged_in():
                return redirect(url_for("login"))
            return render_template_string(
                self._ALERTS_TEMPLATE, rows=self._get_alerts(limit=200))

        @app.route("/api/live")
        def api_live():
            if not self._is_logged_in():
                return jsonify({"error": "unauthorized"}), 401
            stats     = self._ip_db.get_stats()
            pkt_stats = self._analyzer.get_packet_stats()
            return jsonify({
                "blacklist":       stats["blacklist"],
                "whitelist":       stats["whitelist"],
                "total_ips":       stats["total"],
                "alert_count":     self._get_alert_count(),
                "total_packets":   pkt_stats["total"],
                "blocked_packets": pkt_stats["blocked"],
                "recent":          self._get_alerts(limit=10),
                "now":             datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })

        @app.route("/api/alerts")
        def api_alerts():
            if not self._is_logged_in():
                return jsonify({"error": "unauthorized"}), 401
            return jsonify({"rows": self._get_alerts(limit=200)})

    def start(self):
        self._app.run(debug=False, host=self._host,
                      port=self._port, threaded=True)
