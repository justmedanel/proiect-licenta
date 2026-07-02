#Soluție software de rutare pentru echipamente incorporate 

Proiect router în mediul Linux. Sistemul permite rutarea traficului între o interfață externă (WAN) și una internă (LAN), 
monitorizarea în timp real a pachetelor ICMP/TCP printr-o aplicație în **C** (`libpcap`) și gestionarea 
politicilor de rețea (Firewall, Port Forwarding, QoS) printr-o interfață web dezvoltată în **Python (Flask)** 
și **HTML/JavaScript**.

##Adresă repository 
  https://github.com/justmedanel/proiect-licenta

##Structura proiect
* `main.c` - Codul sursă în C pentru motorul de captură și analiză pachete (`libpcap`).
* `app.py` - Aplicația backend în Flask care expune API-ul de control al rețelei (`iptables`, `tc`) și servește interfața grafică.
* `templates/index.html` - Pagina web panou de control (stilizată în temă terminal pentru monitorizare live).

##Instalare și compilare
```bash
##C
   sudo apt update
   sudo apt install libpcap-dev gcc
   gcc -o router_engine main.c -lpcap
##Python/Flask
   sudo apt install python3
   pip install flask
   python3 app.py
```
##Lansare C/Python

   C-ul se lansează când apăsăm butonul de start din interfața web.
   Python se lansează prin python3 app.py.

  
