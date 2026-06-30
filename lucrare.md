# Panou Web de Management pentru un Router Virtual Custom {#mainpage}

## REZUMAT
[cite_start]Proiectul de față reprezintă o soluție hibridă alcătuită dintr-un motor nativ performant dezvoltat în limbajul C și un panou modern de administrare bazat pe un server web Flask (Python) și o interfață HTML statică[cite: 81, 85]. [cite_start]Scopul principal este transformarea unei mașini Linux Ubuntu într-un nod activ de rețea (router/firewall) capabil să asigure funcții de bază în infrastructurile locale LAN/WAN, oferind totodată vizualizare în timp real a pachetelor de rețea de tip ICMP și TCP.

---

## 1. Introducere - Cadrul General
### Motivația alegerii temei
Administrarea rețelelor prin linie de comandă cu `iptables` poate fi greoaie și predispusă la erori umane. [cite_start]Această lucrare abordează simplificarea procesului prin abstractizarea comenzilor critice sub o interfață web intuitivă, utilă administratorilor de sistem.

### Obiectivele generale ale lucrării
* [cite_start]**Captura de nivel scăzut:** Inspectarea headerelor pachetelor IP direct din interfața LAN prin socket-uri raw utilizând `libpcap`.
* [cite_start]**Control Securizat:** Controlul dinamic și curățarea regulilor de rutare NAT/Masquerade din kernel-ul Linux.
* [cite_start]**Interfață Responsivă:** Afișarea fluidă asincronă a fluxului de date prin tehnologii moderne Web.

---

## 2. Structura Tehnică și Capitolele Lucrării
[cite_start]Proiectul este modularizat în trei straturi distincte, reflectate direct în fișierele atașate:
1. **`main.c` (Motorul de Captură):** Scris în C pentru viteză, manipulează pachetele direct din buffer-ul plăcii de rețea.
2. **`app.py` (Backend-ul Flask):** Orchestrează execuția comenzilor de sistem și servește API-ul REST către utilizator.
3. **`index.html` (Interfața de Utilizator):** Construită pentru monitorizare live fără a reîncărca pagina, folosind apeluri AJAX repetitive la interval de 2 secunde.

---

## 3. Concluzii și Direcții Viitoare
Aplicația demonstrează funcționalitatea cu succes a unui sistem de rutare controlat software (SDN) la scară mică. [cite_start]Ca direcții viitoare, se urmărește adăugarea suportului pentru detecția atacurilor de tip DOS (Denial of Service) direct în parserul C și stocarea istoricului de trafic într-o bază de date SQL în loc de fișiere simple `.log`.

---

## DECLARAȚIE DE AUTENTICITATE
[cite_start]Subsemnatul, autor al lucrării elaborate în vederea susținerii examenului de finalizare a studiilor organizat de către Universitatea Politehnica Timișoara, sesiunea Iunie 2026, declar pe proprie răspundere că această lucrare este rezultatul propriei activități intelectuale, iar sursele bibliografice au fost folosite cu respectarea legislației române și a convențiilor internaționale privind drepturile de autor.

Timișoara, Mai 2026