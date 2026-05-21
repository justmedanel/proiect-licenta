from flask import Flask, render_template, jsonify, request
import subprocess
import os

app = Flask(__name__)

WAN = "enp0s3"
LAN = "enp0s8"
LOG_FILE = "traffic.log"

def run_cmd(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    if os.path.exists(LOG_FILE):
        try:
            lines = subprocess.check_output(['tail', '-n', '15', LOG_FILE]).decode('utf-8')
            return jsonify({"traffic": lines})
        except:
            return jsonify({"traffic": "Se procesează pachete..."})
    return jsonify({"traffic": "Niciun trafic detectat."})

@app.route('/api/system', methods=['POST'])
def system_control():
    action = request.json.get('action')
    if action == 'start':
        run_cmd("sudo sysctl -w net.ipv4.ip_forward=1")
        run_cmd(f"sudo iptables -t nat -A POSTROUTING -o {WAN} -j MASQUERADE")
        subprocess.Popen(["sudo", "./router_engine"])
        return jsonify({"msg": "Sistem pornit!"})
    elif action == 'stop':
        run_cmd("sudo iptables -t nat -F")
        run_cmd("sudo iptables -F FORWARD")
        run_cmd("sudo pkill router_engine")
        return jsonify({"msg": "Sistem oprit și reguli curățate."})

@app.route('/api/firewall', methods=['POST'])
def firewall_control():
    ip = request.json.get('ip')
    action = request.json.get('action')
    if action == 'block':
        run_cmd(f"sudo iptables -I FORWARD -s {ip} -j DROP")
        return jsonify({"msg": f"IP {ip} a fost blocat!"})
    else:
        run_cmd(f"sudo iptables -D FORWARD -s {ip} -j DROP")
        return jsonify({"msg": f"IP {ip} a fost deblocat!"})

@app.route('/api/forward', methods=['POST'])
def forward_control():
    action = request.json.get('action')
    # Regula DNAT: Redirecționare port 8080 (Router) către port 80 (Client)
    rule = f"sudo iptables -t nat -A PREROUTING -i {WAN} -p tcp --dport 8080 -j DNAT --to-destination 192.168.10.2:80"
    
    if action == 'enable':
        run_cmd(rule)
        run_cmd("sudo iptables -A FORWARD -p tcp -d 192.168.10.2 --dport 80 -j ACCEPT")
        return jsonify({"msg": "Port Forwarding ACTIVAT (8080 -> 10.2:80)"})
    else:
        run_cmd("sudo iptables -t nat -F") # Resetare NAT
        return jsonify({"msg": "Port Forwarding DEZACTIVAT"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)