from flask import Flask, render_template, jsonify, request
import subprocess
import os

app = Flask(__name__)

##WAN-Internet
WAN = "enp0s3"
##LAN-Local
LAN = "enp0s8"
##Fisier Log-uri
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
    """! Gestionează politicile de securitate (Firewall) pentru blocarea sau deblocarea unui IP țintă.
    @return Mesaj JSON care confirmă dacă IP-ul a fost inserat sau șters din tabelul FORWARD din iptables.
    """
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
    """! Activează sau dezactivează maparea statică de porturi (DNAT - Port Forwarding).
    
    Redirecționează portul extern public 8080 de pe interfața WAN către portul 80 intern al clientului 192.168.10.2.
    @return Mesaj JSON explicativ cu starea curentă a regulii de Port Forwarding.
    """
    action = request.json.get('action')
    rule = f"sudo iptables -t nat -A PREROUTING -i {WAN} -p tcp --dport 8080 -j DNAT --to-destination 192.168.10.2:80"
    
    if action == 'enable':
        run_cmd(rule)
        run_cmd("sudo iptables -A FORWARD -p tcp -d 192.168.10.2 --dport 80 -j ACCEPT")
        return jsonify({"msg": "Port Forwarding ACTIVAT (8080 -> 10.2:80)"})
    else:
        run_cmd("sudo iptables -t nat -F")
        return jsonify({"msg": "Port Forwarding DEZACTIVAT"})

@app.route('/api/qos', methods=['POST'])
def qos_control():
    """! Controlează lățimea de bandă (QoS) pe interfața LAN pentru un IP specificat.
    @return Mesaj JSON de confirmare a aplicării sau eliminării limitării de trafic.
    ```"""
    ip = request.json.get('ip')
    action = request.json.get('action')
    
    if action == 'limit':
        # Resetare configurări vechi
        run_cmd("sudo tc qdisc del dev enp0s8 root 2>/dev/null")
        # Inițializăm coadă de tip HTB (Hierarchical Token Bucket)
        run_cmd("sudo tc qdisc add dev enp0s8 root handle 1: htb default 10")
        # Definim clasa principală limitată la o rată fixă de 5 Mbps
        run_cmd("sudo tc class add dev enp0s8 parent 1: classid 1:10 htb rate 5mbit ceil 5mbit")
        # Aplicăm filtrul u32 pentru a potrivi pachetele care pleacă spre IP-ul destinație din LAN
        run_cmd(f"sudo tc filter add dev enp0s8 parent 1: protocol ip prio 1 u32 match ip dst {ip} flowid 1:10")
        return jsonify({"msg": f"Lățime de bandă limitată la 5 Mbps pentru IP-ul {ip}!"})
    else:
        # Eliminăm disciplina de coadă și redăm banda maximă interfeței
        run_cmd("sudo tc qdisc del dev enp0s8 root")
        return jsonify({"msg": f"Limitarea de viteză pentru {ip} a fost eliminată."})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
