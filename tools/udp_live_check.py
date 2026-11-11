"""Live check of UDP (Hysteria 2) tweaks: starts a real Xray Hysteria 2 server, builds the client config exactly as the
admin panel and the app do, and sends a web request through it.

    cd control-plane && mkdir -p /tmp/udptest && cd /tmp/udptest
    XRAY=/path/to/xray python /path/to/control-plane/tools/udp_live_check.py

Download Xray 26.3.27 for your system from https://github.com/XTLS/Xray-core/releases/tag/v26.3.27 . Needs openssl and curl.
"Must NOT connect" lines are expected to print FAIL: that is the wrong password and the untrusted certificate being refused.
"""
import json, os, subprocess, sys, time, hashlib, signal, threading, http.server, socketserver
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from services import links

XRAY = os.environ.get("XRAY", "xray")   # the Xray binary, version 26.3.27 (same as inside the app)
# ---- a self-signed certificate for udp.test, and its SHA-256 fingerprint
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "key.pem", "-out", "cert.pem", "-days", "2",
                "-subj", "/CN=udp.test", "-addext", "subjectAltName=DNS:udp.test"], check=True, capture_output=True)
der = subprocess.run(["openssl", "x509", "-in", "cert.pem", "-outform", "der"], check=True, capture_output=True).stdout
FP = hashlib.sha256(der).hexdigest()

# ---- the website the tunnel should reach
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"HELLO-FROM-THE-OTHER-SIDE")
    def log_message(self, *a): pass
srv = socketserver.TCPServer(("127.0.0.1", 8099), H); threading.Thread(target=srv.serve_forever, daemon=True).start()

def server_cfg(port, auth="bob:pw"):
    return {"log": {"loglevel": "warning"},
            "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "hysteria",
                          "settings": {"version": 2, "clients": [{"auth": auth, "level": 0, "email": "bob"}]},
                          "streamSettings": {"network": "hysteria", "security": "tls",
                                             "tlsSettings": {"alpn": ["h3"], "certificates": [{"certificateFile": "" + os.getcwd() + "/cert.pem", "keyFile": "" + os.getcwd() + "/key.pem"}]},
                                             "hysteriaSettings": {"version": 2}}}],
            "outbounds": [{"protocol": "freedom"}]}

def app_cfg(outbound, full=False):
    """Port of XrayConfig.build() in the app. The test run drops the tun inbound (a container cannot make one)."""
    inbounds = [{"tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"udp": True, "auth": "noauth"}}]
    if full:
        inbounds.insert(0, {"tag": "tun-in", "protocol": "tun", "settings": {"name": "xray0", "MTU": 1500, "userLevel": 0},
                            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}})
    return {"log": {"loglevel": "warning"}, "dns": {"servers": ["tcp://1.1.1.1", "tcp://8.8.8.8"], "queryStrategy": "UseIPv4"},
            "inbounds": inbounds,
            "outbounds": [outbound, {"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}, {"tag": "dns-out", "protocol": "dns"}],
            "routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "inboundTag": ["tun-in"], "port": "53", "outboundTag": "dns-out"}]}}

def write(name, obj):
    json.dump(obj, open(name, "w")); return name

def config_test(name):
    r = subprocess.run([XRAY, "run", "-test", "-c", name], capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip().splitlines()[-1][:300] if (r.stdout + r.stderr).strip() else ""

def e2e(label, outbound, port, server_auth="bob:pw", wait=1.5, fetch_seconds=12):
    sp = subprocess.Popen([XRAY, "run", "-c", write("srv.json", server_cfg(port, server_auth))], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(1.2)
    cp = subprocess.Popen([XRAY, "run", "-c", write("cli.json", app_cfg(outbound))], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(wait)
    t0 = time.time()
    r = subprocess.run(["curl", "-s", "-m", str(fetch_seconds), "--socks5-hostname", "127.0.0.1:10808", "http://127.0.0.1:8099/"], capture_output=True, text=True)
    took = time.time() - t0
    for p in (cp, sp):
        p.terminate()
    time.sleep(0.4)
    ok = "HELLO-FROM-THE-OTHER-SIDE" in r.stdout
    logs = ""
    try:
        logs = (cp.communicate(timeout=3)[0] or "").strip().splitlines()
        logs = " | ".join(l[-140:] for l in logs[-2:])
    except Exception:
        pass
    print(f"{'PASS' if ok else 'FAIL'}  {label}  ({took:.1f}s)" + ("" if ok else f"   client log: {logs}"))
    return ok

print("engine:", subprocess.run([XRAY, "version"], capture_output=True, text=True).stdout.splitlines()[0])
print("cert fingerprint:", FP[:16] + "…")

# 1. the original bug, reproduced: the config the previous version produced
legacy = {"protocol": "hysteria", "tag": "proxy", "settings": {"version": 2, "address": "127.0.0.1", "port": 4443},
          "streamSettings": {"network": "hysteria", "security": "tls", "tlsSettings": {"serverName": "udp.test", "alpn": ["h3"], "allowInsecure": True},
                             "hysteriaSettings": {"version": 2, "auth": "bob:pw"}}}
ok, msg = config_test(write("legacy.json", app_cfg(legacy, full=True)))
print(("PASS" if ok else "REPRODUCED") + "  old config (allowInsecure):", msg)
ok, msg = config_test(write("legacy_fixed.json", app_cfg(links.clean_outbound(legacy), full=True)))
print(("PASS" if ok else "FAIL") + "  old config after clean_outbound:", msg or "accepted")

# 2. the new panel output, the app's full config (with the tun inbound)
pin = ":".join(FP[i:i + 2].upper() for i in range(0, 64, 2))
single = links.build_udp("127.0.0.1", "4443", "bob", "pw", sni="udp.test", pin=pin)
ok, msg = config_test(write("full.json", app_cfg(single, full=True)))
print(("PASS" if ok else "FAIL") + "  new panel config, full app config incl. tun:", msg or "accepted")

# 3. real traffic through a real Hysteria 2 server
results = []
results.append(e2e("single port, pinned certificate, user bob / pw", single, 4443))
results.append(e2e("wrong password is refused (must NOT connect)", links.build_udp("127.0.0.1", "4443", "bob", "WRONG", sni="udp.test", pin=pin), 4443, wait=1.0, fetch_seconds=6) is False)
results.append(e2e("untrusted certificate with no fingerprint is refused (must NOT connect)", links.build_udp("127.0.0.1", "4443", "bob", "pw", sni="udp.test"), 4443, wait=1.0, fetch_seconds=6) is False)
hop = links.build_udp("127.0.0.1", "4443-4448", "bob", "pw", sni="udp.test", pin=pin)
print("hop outbound finalmask:", json.dumps(hop["streamSettings"]["finalmask"]))
results.append(e2e("port range 4443-4448 with hopping", hop, "4443-4448"))
os._exit(0 if all(results) else 1)
