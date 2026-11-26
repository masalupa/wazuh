#!/usr/bin/env python3
"""
install_wazuh_agent_v2.py

Automation untuk instalasi Wazuh AGENT, dijalankan LANGSUNG di komputer
customer (laptop/PC/server) - Linux atau Windows. Tidak memakai SSH sama
sekali: script ini mendeteksi OS tempat ia berjalan, lalu menginstal dan
mengonfigurasi agent di komputer itu sendiri.

Mendukung IP Wazuh manager PRIMARY dan BACKUP (failover) sekaligus, dengan
dua agent group yang berbeda nama, lewat <server> block ganda di
ossec.conf.

Cara pakai
----------
1) Mode INTERAKTIF (paling cocok untuk teknisi di laptop customer - tinggal
   jalankan tanpa argumen apa pun, lalu ikuti pertanyaan di layar):

   Linux  (jalankan dengan sudo):
       sudo python3 install_wazuh_agent_v2.py

   Windows (jalankan PowerShell/CMD sebagai Administrator):
       python install_wazuh_agent_v2.py

2) Mode NON-INTERAKTIF (untuk dijalankan lewat script lain / silent):

   sudo python3 install_wazuh_agent_v2.py \
       --primary-ip 192.168.1.100 \
       --backup-ip 203.0.113.50 \
       --agent-name laptop-budi \
       --group customer-laptop \
       --yes

   --yes akan melewati semua prompt konfirmasi (dipakai untuk automation
   penuh / silent install).

Catatan
-------
- Script ini menginstal paket Wazuh agent RESMI dari repo packages.wazuh.com.
- Sesuaikan versi di WAZUH_MAJOR_MINOR / WAZUH_VERSION_* di bawah supaya
  SAMA dengan versi Wazuh manager customer (atau satu versi di bawahnya).
- Wajib dijalankan dengan hak admin/root.
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import xml.etree.ElementTree as ET

WAZUH_MAJOR_MINOR = "4.9"
WAZUH_VERSION_DEB = "4.9.0-1"
WAZUH_VERSION_RPM = "4.9.0-1"
WAZUH_VERSION_WIN = "4.9.0-1"


# --------------------------------------------------------------------------- #
# Helpers umum
# --------------------------------------------------------------------------- #

def run(cmd, check=True, shell=False):
    print(f"[+] Menjalankan: {cmd if isinstance(cmd, str) else ' '.join(cmd)}")
    return subprocess.run(cmd, shell=shell, check=check)


def is_admin_windows():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def is_root_linux():
    return os.geteuid() == 0


def download(url, dest):
    print(f"[+] Mengunduh {url} -> {dest}")
    urllib.request.urlretrieve(url, dest)


def ask(prompt_text, default=None, required=False):
    """Prompt interaktif sederhana dengan default value opsional."""
    suffix = f" [{default}]" if default else ""
    while True:
        val = input(f"{prompt_text}{suffix}: ").strip()
        if not val and default is not None:
            return default
        if not val and required:
            print("    -> Wajib diisi, coba lagi.")
            continue
        return val or None


def confirm(prompt_text, default_yes=True):
    suffix = "[Y/n]" if default_yes else "[y/N]"
    val = input(f"{prompt_text} {suffix}: ").strip().lower()
    if not val:
        return default_yes
    return val in ("y", "yes", "ya")


# --------------------------------------------------------------------------- #
# Linux install
# --------------------------------------------------------------------------- #

def detect_linux_family():
    if shutil.which("apt-get") or shutil.which("apt"):
        return "debian"
    if shutil.which("yum") or shutil.which("dnf"):
        return "rhel"
    raise RuntimeError("Distribusi Linux tidak didukung (tidak ada apt atau yum/dnf).")


def install_linux_agent():
    family = detect_linux_family()

    if family == "debian":
        run(["apt-get", "update", "-y"])
        run(["apt-get", "install", "-y", "gnupg", "apt-transport-https", "curl"])
        run(
            "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | "
            "gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && "
            "chmod 644 /usr/share/keyrings/wazuh.gpg",
            shell=True,
        )
        repo_line = (
            f"deb [signed-by=/usr/share/keyrings/wazuh.gpg] "
            f"https://packages.wazuh.com/{WAZUH_MAJOR_MINOR}/apt/ stable main"
        )
        with open("/etc/apt/sources.list.d/wazuh.list", "w") as f:
            f.write(repo_line + "\n")
        run(["apt-get", "update", "-y"])
        run(["apt-get", "install", "-y", f"wazuh-agent={WAZUH_VERSION_DEB}"])

    else:  # rhel family
        repo_content = f"""[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/{WAZUH_MAJOR_MINOR}/yum/
protect=1
"""
        with open("/etc/yum.repos.d/wazuh.repo", "w") as f:
            f.write(repo_content)
        pkg_mgr = "dnf" if shutil.which("dnf") else "yum"
        run([pkg_mgr, "install", "-y", f"wazuh-agent-{WAZUH_VERSION_RPM}"])


def write_server_blocks_linux(conf_path, primary_ip, backup_ip, port, protocol):
    tree = ET.parse(conf_path)
    root = tree.getroot()
    client = root.find("client")
    if client is None:
        client = ET.SubElement(root, "client")

    for server_el in client.findall("server"):
        client.remove(server_el)

    def add_server(ip):
        server_el = ET.SubElement(client, "server")
        ET.SubElement(server_el, "address").text = ip
        ET.SubElement(server_el, "port").text = str(port)
        ET.SubElement(server_el, "protocol").text = protocol

    add_server(primary_ip)
    if backup_ip:
        add_server(backup_ip)

    tree.write(conf_path, encoding="ISO-8859-1", xml_declaration=False)
    print(f"[+] {conf_path} diperbarui: primary={primary_ip}"
          + (f", backup={backup_ip}" if backup_ip else ""))


def configure_linux_agent(primary_ip, backup_ip, agent_name, group, port, protocol):
    conf_path = "/var/ossec/etc/ossec.conf"
    write_server_blocks_linux(conf_path, primary_ip, backup_ip, port, protocol)

    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "wazuh-agent"])
    run(["systemctl", "restart", "wazuh-agent"])

    # Registrasi manual (agent-auth) jika manager belum auto-enroll via autentikasi password
    if agent_name or group:
        cmd = ["/var/ossec/bin/agent-auth", "-m", primary_ip]
        if agent_name:
            cmd += ["-A", agent_name]
        if group:
            cmd += ["-G", group]
        print("[i] Mencoba registrasi manual ke manager (agent-auth)...")
        try:
            run(cmd, check=False)
        except FileNotFoundError:
            print("[!] agent-auth tidak ditemukan - lewati registrasi manual, gunakan auto-enrollment biasa.")


# --------------------------------------------------------------------------- #
# Windows install
# --------------------------------------------------------------------------- #

def install_and_configure_windows(primary_ip, backup_ip, agent_name, group, port, protocol):
    msi_url = (
        f"https://packages.wazuh.com/{WAZUH_MAJOR_MINOR}/windows/"
        f"wazuh-agent-{WAZUH_VERSION_WIN}.msi"
    )
    tmp_dir = tempfile.gettempdir()
    msi_path = os.path.join(tmp_dir, "wazuh-agent.msi")
    download(msi_url, msi_path)

    manager_value = primary_ip
    if backup_ip:
        manager_value = f"{primary_ip},{backup_ip}"

    msiexec_args = [
        "msiexec.exe", "/i", msi_path,
        f"WAZUH_MANAGER={manager_value}",
        f"WAZUH_REGISTRATION_SERVER={primary_ip}",
        "/q",
    ]
    if agent_name:
        msiexec_args.append(f"WAZUH_AGENT_NAME={agent_name}")
    if group:
        msiexec_args.append(f"WAZUH_AGENT_GROUP={group}")

    run(msiexec_args)

    conf_path = r"C:\Program Files (x86)\ossec-agent\ossec.conf"
    if os.path.exists(conf_path):
        write_server_blocks_linux(conf_path, primary_ip, backup_ip, port, protocol)

    run(["net", "stop", "wazuh"], check=False)
    run(["net", "start", "wazuh"])


# --------------------------------------------------------------------------- #
# Alur interaktif
# --------------------------------------------------------------------------- #

def gather_interactive_inputs(args):
    print("=" * 60)
    print(" Instalasi Wazuh Agent - mode interaktif")
    print("=" * 60)

    if not args.primary_ip:
        args.primary_ip = ask("IP/hostname Wazuh manager UTAMA (primary)", required=True)
    if args.backup_ip is None:
        has_backup = confirm("Apakah ada Wazuh manager CADANGAN (backup/failover)?", default_yes=False)
        if has_backup:
            args.backup_ip = ask("IP/hostname Wazuh manager CADANGAN (backup)", required=True)
    if not args.agent_name:
        hostname_default = platform.node()
        args.agent_name = ask("Nama agent (kosongkan untuk pakai hostname komputer)", default=hostname_default)
    if not args.group:
        args.group = ask("Nama grup agent (kosongkan jika tidak perlu)", default="")
        if args.group == "":
            args.group = None

    print("-" * 60)
    print(f" Primary manager : {args.primary_ip}")
    print(f" Backup manager  : {args.backup_ip or '(tidak diset)'}")
    print(f" Nama agent      : {args.agent_name}")
    print(f" Grup            : {args.group or '(default)'}")
    print(f" Port / Protokol : {args.port} / {args.protocol}")
    print("-" * 60)

    if not args.yes and not confirm("Lanjutkan instalasi dengan pengaturan di atas?"):
        sys.exit("Dibatalkan oleh pengguna.")

    return args


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        description="Instal & konfigurasi Wazuh agent di komputer ini (Linux/Windows), tanpa SSH."
    )
    parser.add_argument("--primary-ip", default=None, help="IP/hostname Wazuh manager utama (primary).")
    parser.add_argument("--backup-ip", default=None, help="IP/hostname Wazuh manager cadangan (backup/failover).")
    parser.add_argument("--agent-name", default=None, help="Nama agent (default: nama komputer).")
    parser.add_argument("--group", default=None, help="Nama grup agent di manager.")
    parser.add_argument("--port", type=int, default=1514, help="Port manager (default: 1514).")
    parser.add_argument("--protocol", choices=["tcp", "udp"], default="tcp", help="Protokol (default: tcp).")
    parser.add_argument("--yes", action="store_true",
                         help="Lewati semua prompt konfirmasi (mode silent/non-interaktif).")
    args = parser.parse_args()

    # Jika primary IP belum diberikan lewat argumen, masuk ke mode interaktif
    if not args.primary_ip:
        args = gather_interactive_inputs(args)
    elif not args.yes:
        args = gather_interactive_inputs(args)  # tetap tampilkan ringkasan & minta konfirmasi

    system = platform.system()

    if system == "Linux":
        if not is_root_linux():
            sys.exit("[-] Jalankan script ini dengan sudo (root).")
        install_linux_agent()
        configure_linux_agent(
            args.primary_ip, args.backup_ip, args.agent_name,
            args.group, args.port, args.protocol,
        )
        print("\n[+] Selesai. Cek status: systemctl status wazuh-agent")
        print("[+] Cek log      : tail -f /var/ossec/logs/ossec.log")

    elif system == "Windows":
        if not is_admin_windows():
            sys.exit("[-] Jalankan dari PowerShell/CMD sebagai Administrator.")
        install_and_configure_windows(
            args.primary_ip, args.backup_ip, args.agent_name,
            args.group, args.port, args.protocol,
        )
        print(r'\n[+] Selesai. Cek log: Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 30')

    else:
        sys.exit(f"[-] OS tidak didukung: {system}")


if __name__ == "__main__":
    main()
