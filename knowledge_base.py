"""
knowledge_base.py - plain-English knowledge about well-known network ports.

analyze_port() is called once per listening port by backend.collect_network_facts().
It returns a "finding" dict that the rest of the app understands.
"""

LOOPBACK = ("127.0.0.1", "::1")

# port -> (service, plain title, what it is, risk if reachable from the network, why that matters, fix)
_PORTS = {
    21: ("FTP", "File transfer server (FTP)", "an FTP file server", "High",
         "FTP sends passwords and files without encryption, so anyone on the network could read them.",
         "If you did not set up file sharing on purpose, close the program that opened it. Otherwise use SFTP instead."),
    22: ("SSH", "Remote login server (SSH)", "a remote-login (SSH) server", "Medium",
         "Anyone on the network can try to log in to this computer remotely.",
         "If you do not use remote login, turn the SSH server off. If you do, make sure it uses strong passwords or keys."),
    23: ("Telnet", "Old remote login (Telnet)", "a Telnet remote-login server", "High",
         "Telnet is unencrypted and very old. Attackers scan the internet for it all the time.",
         "Turn Telnet off in Windows Features. There is almost never a good reason to leave it on."),
    25: ("SMTP", "Mail server (SMTP)", "a mail-sending server", "Medium",
         "A mail server reachable from the network can be abused to send spam.",
         "If you do not run a mail server on purpose, close the program that opened it."),
    53: ("DNS", "Name lookup server (DNS)", "a DNS name-lookup server", "Medium",
         "Other devices can use this computer to look up internet names, which is unusual for a PC.",
         "Unless you run a DNS server on purpose (or share your connection), close the program."),
    80: ("HTTP", "Web server (HTTP)", "a web server", "Medium",
         "Other devices on your network can open web pages served from this computer.",
         "If you are not hosting a site or testing something, close the program that opened it."),
    110: ("POP3", "Mail server (POP3)", "an old-style mail server", "Medium",
          "POP3 mail is usually not encrypted.", "Close the program unless you run a mail server on purpose."),
    111: ("RPC", "Network file helper (RPC)", "a network-file helper service", "Medium",
          "It can expose details about file sharing on this computer.",
          "If you do not use network file sharing, turn the service off."),
    135: ("Windows RPC", "Windows background service", "a standard Windows service", "Low",
          "This is normal on every Windows PC.", "Nothing to do."),
    139: ("NetBIOS", "Windows file sharing (NetBIOS)", "old-style Windows file sharing", "Medium",
          "On public Wi-Fi, strangers could see this computer's shared files and try to connect.",
          "On public networks, set the connection to 'Public' and turn off file and printer sharing."),
    143: ("IMAP", "Mail server (IMAP)", "a mail server", "Medium",
          "IMAP mail is often not encrypted.", "Close the program unless you run a mail server on purpose."),
    389: ("LDAP", "Directory server (LDAP)", "a directory (LDAP) server", "Medium",
          "It can reveal account details to other devices.", "Close it unless this is a company server."),
    443: ("HTTPS", "Secure web server (HTTPS)", "a secure web server", "Medium",
          "Other devices on your network can reach a website served from this computer.",
          "If you are not hosting a site or testing something, close the program that opened it."),
    445: ("SMB", "Windows file sharing (SMB)", "Windows file and printer sharing", "Medium",
          "On public Wi-Fi, strangers could try to reach your shared files.",
          "On public networks, set the connection to 'Public' and turn off file and printer sharing."),
    1433: ("SQL Server", "Database server (SQL Server)", "a Microsoft SQL Server database", "High",
           "Databases should not be reachable from the network. Attackers guess passwords against them.",
           "Make the database listen on this computer only, or block it in the firewall."),
    1883: ("MQTT", "Smart-device messaging (MQTT)", "an MQTT message broker", "Medium",
           "Messages are usually unprotected by default.", "Limit it to this computer unless you rely on it."),
    2049: ("NFS", "Network file sharing (NFS)", "an NFS file share", "Medium",
           "Files may be reachable from other devices.", "Turn it off if you do not share files this way."),
    2375: ("Docker", "Docker control port (unprotected)", "an unprotected Docker control port", "High",
           "Anyone who can reach it can take full control of this computer.",
           "Turn off 'Expose daemon on tcp://localhost:2375 without TLS' in Docker settings."),
    3000: ("Dev server", "Development web server", "a development web server", "Medium",
           "Test servers often have no password and show private project data.",
           "Stop the dev server when you are done, or make it listen on this computer only."),
    3306: ("MySQL", "Database server (MySQL)", "a MySQL database", "High",
           "Databases should not be reachable from the network. Attackers guess passwords against them.",
           "Set bind-address to 127.0.0.1 or block it in the firewall."),
    3389: ("RDP", "Remote Desktop", "Windows Remote Desktop", "High",
           "Attackers constantly try to break into Remote Desktop. It is a common way PCs get taken over.",
           "If you do not use Remote Desktop, turn it off in Windows Settings. If you do, use a VPN and a strong password."),
    5000: ("Dev server", "Development web server", "a development web server", "Medium",
           "Test servers often have no password and show private project data.",
           "Stop the dev server when you are done, or make it listen on this computer only."),
    5037: ("ADB", "Android debugging helper", "the Android debugging helper (ADB)", "Medium",
           "Other devices could talk to it and control a connected phone.",
           "Run 'adb kill-server' when you are not developing."),
    5040: ("Windows", "Windows background service", "a standard Windows service", "Low",
           "This is normal on Windows 10 and 11.", "Nothing to do."),
    5357: ("WSD", "Windows device discovery", "Windows device discovery", "Low",
           "This is normal on Windows. It helps find printers and devices.", "Nothing to do."),
    5432: ("PostgreSQL", "Database server (PostgreSQL)", "a PostgreSQL database", "High",
           "Databases should not be reachable from the network. Attackers guess passwords against them.",
           "Set listen_addresses to localhost or block it in the firewall."),
    5601: ("Kibana", "Dashboard server (Kibana)", "a Kibana dashboard", "Medium",
           "Dashboards can show private data to anyone on the network.", "Limit it to this computer."),
    5672: ("RabbitMQ", "Message server (RabbitMQ)", "a RabbitMQ message server", "Medium",
           "Unprotected message servers can leak or accept data.", "Limit it to this computer."),
    5900: ("VNC", "Remote screen sharing (VNC)", "VNC remote screen sharing", "High",
           "Someone who can reach it could watch or control your screen.",
           "Close the VNC server unless you use it on purpose, and set a strong password."),
    5985: ("WinRM", "Remote management (WinRM)", "Windows remote management", "High",
           "It lets other computers run commands on this one if they have the right login.",
           "Turn it off with 'Disable-PSRemoting' if you do not use it."),
    5986: ("WinRM", "Remote management (WinRM, secure)", "Windows remote management", "Medium",
           "It lets other computers run commands on this one if they have the right login.",
           "Turn it off with 'Disable-PSRemoting' if you do not use it."),
    6000: ("X11", "Remote window server (X11)", "an X11 window server", "Medium",
           "Other devices might be able to see or control windows.", "Close it unless you need it."),
    6379: ("Redis", "Database server (Redis)", "a Redis database", "High",
           "Redis often has no password, so anyone on the network could read or change the data.",
           "Bind Redis to 127.0.0.1 and set a password."),
    7680: ("Windows", "Windows update sharing", "Windows Update sharing (Delivery Optimization)", "Low",
           "This is normal. Windows shares update files with other PCs.",
           "Nothing to do. You can turn it off in Windows Update settings."),
    8000: ("Dev server", "Development web server", "a development web server", "Medium",
           "Test servers often have no password and show private project data.",
           "Stop the dev server when you are done, or make it listen on this computer only."),
    8080: ("Web (alt)", "Web server (port 8080)", "a web server", "Medium",
           "Other devices on your network can open pages served from this computer.",
           "If you are not hosting or testing something, close the program that opened it."),
    8443: ("Web (alt)", "Secure web server (port 8443)", "a secure web server", "Medium",
           "Other devices on your network can reach a site served from this computer.",
           "If you are not hosting or testing something, close the program that opened it."),
    8888: ("Jupyter", "Notebook / dev server", "a notebook or development server", "Medium",
           "Notebook servers can run code. Without a password, anyone on the network could use it.",
           "Stop it when you are done, or make it listen on this computer only."),
    9100: ("Printer", "Printer port", "a raw printer port", "Medium",
           "Anyone on the network could send print jobs to it.", "Close it unless you share this printer."),
    9200: ("Elasticsearch", "Search database (Elasticsearch)", "an Elasticsearch database", "High",
           "It often has no password, so anyone on the network could read or delete the data.",
           "Bind it to localhost and turn on security."),
    11434: ("Ollama", "Local AI server (Ollama)", "a local AI model server", "Medium",
            "Other devices could use your computer to run AI models.",
            "Set OLLAMA_HOST to 127.0.0.1 unless you share it on purpose."),
    27017: ("MongoDB", "Database server (MongoDB)", "a MongoDB database", "High",
            "MongoDB has often been left open without a password, so data gets stolen.",
            "Bind it to 127.0.0.1 and turn on authentication."),
}

# Ranges: 5900-5902 VNC displays, 5000-5001 etc. are handled by direct lookup above.
_ALIASES = {5901: 5900, 5902: 5900}


def _is_local(ip):
    return ip in LOOPBACK or (ip or "").startswith("127.")


def analyze_port(port, process_name, pid, listen_ip, exe_path=""):
    """Return a finding dict for one listening port."""
    port = int(port)
    is_local = _is_local(listen_ip)
    exposure = "Local only" if is_local else "Network"
    entry = _PORTS.get(_ALIASES.get(port, port))
    name = process_name or "an unknown program"

    base = {
        "port": port,
        "process": process_name,
        "pid": pid,
        "exe": exe_path or "Run as administrator to inspect program location",
        "ip": listen_ip,
        "exposure": exposure,
    }

    if entry:
        service, title, what, base_risk, why, fix = entry
        return dict(
            base,
            service=service,
            plain_title=title,
            risk="Low" if is_local else base_risk,
            base_risk=base_risk,
            unknown=False,
            description=f"The program '{name}' is running {what} on port {port}.",
            business_impact=("Protected: only this computer can reach it." if is_local else why),
            fix=fix if not is_local else "Nothing to do. It only listens on this computer.",
        )

    return dict(
        base,
        service="Background program",
        plain_title=f"Program listening on port {port}",
        risk="Low" if is_local else "Medium",
        base_risk="Medium",
        unknown=True,
        description=f"The program '{name}' is waiting for connections on port {port}.",
        business_impact=(
            "Protected: only this computer can reach it."
            if is_local
            else "Other devices on your network may be able to reach this program."
        ),
        fix="If you do not recognize this program, close it and run a security scan.",
    )
