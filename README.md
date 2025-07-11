# Logan2 - HackMyVM - Medium

**Schwierigkeitsgrad:** Medium 🟡

---

## ℹ️ Maschineninformationen

*   **Plattform:** HackMyVM
*   **VM Link:** [https://hackmyvm.eu/machines/machine.php?vm=Logan2](https://hackmyvm.eu/machines/machine.php?vm=Logan2)
*   **Autor:** DarkSpirit

![Logan2 Machine Icon](Logan2.png)

---

## 🏁 Übersicht

Dieser Bericht dokumentiert den Penetrationstest der virtuellen Maschine "Logan2" von HackMyVM. Das Ziel war die Erlangung von Systemzugriff und die Ausweitung der Berechtigungen bis auf Root-Ebene. Die Maschine wies mehrere Schwachstellen auf, darunter eine SQL Injection, eine Local File Inclusion (LFI) kombiniert mit Log Poisoning zur Erlangung von Initial Access als `www-data`, sowie eine Sudo-Fehlkonfiguration, die zur Ausführung eines Root-Debuggers und damit zur Erlangung vollständiger Root-Rechte führte.

---

## 📖 Zusammenfassung des Walkthroughs

Der Pentest gliederte sich in folgende Hauptphasen:

### 🔎 Reconnaissance

*   Identifizierung der Ziel-IP (192.168.2.35) im lokalen Netzwerk mittels `arp-scan`.
*   Hinzufügen des Hostnamens `logan.hmv` zur lokalen `/etc/hosts`.
*   Umfassender Portscan (`nmap`), der Port 22 (SSH), Port 80 (HTTP - Apache) und Port 3000 (HTTP - Gitea 1.12.5) als offen identifizierte.

### 🌐 Web Enumeration

*   Scan des Apache-Webservers auf Port 80 mit `nikto`, der fehlende Sicherheits-Header, ETag-Informationslecks und das Vorhandensein von `/config.php` identifizierte.
*   Verzeichnis-Brute-Force mit `feroxbuster` bestätigte `/config.php` und fand weitere Dateien wie `/script.js` und `/save-user-agent.php`.
*   Analyse von `/script.js` zeigte, dass eine POST-Anfrage mit JSON-Daten (inkl. `user_agent`) an `/save-user-agent.php` gesendet wird.
*   Ausnutzung einer zeitbasierten Blind SQL Injection im `user_agent`-Parameter von `/save-user-agent.php` mittels `sqlmap` zur Enumeration der Datenbank `logan` und der Tabelle `users`.
*   Extraktion des Benutzernamens `logan` und der Subdomain `newsitelogan.logan.hmv` aus der `users` Tabelle.
*   Verifizierung der Subdomain `newsitelogan.logan.hmv`, die ebenfalls auf Port 80 gehostet wird und das Skript `/photos-website-logan.php` verwendet.
*   Analyse des Skripts `/photos-website-logan.php` zeigte einen `photo`-Parameter, der für LFI anfällig ist.
*   Ausnutzung der LFI-Schwachstelle (`/photos-website-logan.php?photo=../../../../../../var/log/apache2/access.log`) zum Auslesen des Apache Access Logs.
*   Identifizierung einer regelmäßigen Reinigung des Access Logs.
*   Prüfung der PHP-Konfiguration via Log Poisoning zeigte deaktivierte Funktionen (`system`, `exec`, etc.), aber `include()` war erlaubt.
*   Ausnutzung der LFI/Log Poisoning Kette mittels PHP-Filtern (`php://filter/convert.base64-encode`) zum Auslesen der Datei `/var/www/logan/config.php`.
*   Dekodierung der base64-Ausgabe von `/var/www/logan/config.php`, die die Datenbank-Anmeldedaten (`logan`/`Super_logan1234`) enthielt.

### 💻 Initialer Zugriff

*   Verwendung der gefundenen Anmeldedaten (`logan`/`Super_logan1234`) für die Anmeldung bei der Gitea-Instanz auf Port 3000.
*   Ausnutzung der bekannten Gitea Git Hooks RCE Schwachstelle (CVE-2020-14144) für authentifizierte Benutzer mittels Metasploit.
*   Erfolgreiche Erlangung einer Meterpreter/Reverse Shell als Benutzer `git` (der Gitea-Dienstbenutzer).

### 📈 Privilege Escalation

*   Von der `git` Shell: System-Enumeration und Prüfung der `sudo`-Berechtigungen (`sudo -l`).
*   Identifizierung einer kritischen Sudo-Fehlkonfiguration: Benutzer `git` darf `/usr/bin/python3 /opt/app.py` als Root ohne Passwort ausführen (`(ALL) NOPASSWD: /usr/bin/python3 /opt/app.py`).
*   Ausführung des Python-Skripts `/opt/app.py` als Root mittels `sudo /usr/bin/python3 /opt/app.py`.
*   Die Ausführung des Skripts startete eine Flask-Webanwendung mit aktiviertem Werkzeug Debugger auf Port 8000 und gab den Debugger-PIN (`428-583-209`) im Standard-Output aus.
*   Zugriff auf die Werkzeug Debugger Konsole auf Port 8000.
*   Eingabe des erhaltenen PINs zur Freischaltung der Konsole.
*   Ausnutzung der freigeschalteten Debugger Konsole zur Ausführung von Python-Code mit Root-Berechtigungen.
*   Initiierung einer Reverse Shell zum Angreifer-System mittels Python-Code in der Konsole.
*   Erfolgreiche Erlangung einer stabilen Root-Shell.

### 🚩 Flags

*   **User Flag:** Gefunden in `/home/logan/user.txt`
    ` User Flag: 24671329416324134234 `
*   **Root Flag:** Gefunden in `/root/root.txt`
    ` Root flag: 1290381293128301a `

---

## 🧠 Wichtige Erkenntnisse

*   **SQL Injection (Blind):** Auch Blind SQL Injection kann zur vollständigen Kompromittierung von Datenbankinhalten führen. Strikte Validierung und parametrisierte Abfragen sind unerlässlich.
*   **Subdomain Enumeration:** Informationen aus Datenlecks (wie E-Mail-Adressen) können auf die Existenz weiterer Dienste oder Subdomains hinweisen, die zusätzliche Angriffsflächen bieten.
*   **Local File Inclusion (LFI) & Log Poisoning:** LFI-Schwachstellen, insbesondere in Kombination mit schreibbaren und inkludierbaren Logdateien, sind ein direkter Weg zu RCE.
*   **PHP Filter Chains:** PHP Filter können zur Umgehung von WAFs oder zur exfiltration von Code/Daten genutzt werden, auch wenn Systemausführungsfunktionen deaktiviert sind.
*   **Kompromittierung von Zugangsdaten:** Unsichere Speicherung von Anmeldedaten (z.B. in Konfigurationsdateien oder Browserprofilen) kann weitreichende Folgen haben.
*   **Bekannte Schwachstellen in Anwendungen:** Veraltete Software (wie Gitea 1.12.5) enthält oft öffentlich bekannte Schwachstellen, die leicht ausgenutzt werden können.
*   **Kritische Sudo-Fehlkonfigurationen:** Die Erlaubnis, beliebige Skripte oder Interpreter mit Root-Rechten ohne Passwort auszuführen, ist ein direkter Weg zur Systemkompromittierung.
*   **Root Debugger mit offenem PIN:** Ein aktivierter Debugger, der mit Root-Rechten läuft und dessen PIN leicht zugänglich ist, stellt eine extrem schwerwiegende RCE-Schwachstelle dar.

---

## 📄 Vollständiger Bericht

Eine detaillierte Schritt-für-Schritt-Anleitung, inklusive Befehlsausgaben, Analyse, Bewertung und Empfehlungen für jeden Schritt, finden Sie im vollständigen HTML-Bericht:

[**➡️ Vollständigen Pentest-Bericht hier ansehen**](https://alientec1908.github.io/Logan2_HackMyVM_Medium/)

---

*Berichtsdatum: 10. Juni 2025*
*Pentest durchgeführt von DarkSpirit*
