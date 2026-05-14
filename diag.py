#!/usr/bin/env python3
"""
Tor-VPN Manager — module de diagnostic IA
Utilisé par :
  - gui.py  (_run_diagnostic)  via  import diag
  - CLI     (tor-vpn diag)     via  python3 diag.py [options]
"""

import subprocess
import json
import sys
import os
import time
import argparse
import urllib.request
from pathlib import Path


# ── Collecte système ──────────────────────────────────────────────────────────

def _run(cmd: list, timeout: int = 6) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout + r.stderr).strip()
        return out if out else "(vide)"
    except FileNotFoundError:
        return f"(commande introuvable : {cmd[0]})"
    except subprocess.TimeoutExpired:
        return "(timeout)"
    except Exception as e:
        return f"(erreur : {e})"


def collect_diag() -> dict:
    sections = {}

    sections["systemd_service"] = _run(
        ["systemctl", "status", "tor-vpn-manager", "--no-pager", "-l"])

    sections["tor_process"] = _run(["pgrep", "-a", "tor"])

    sections["openvpn_process"] = _run(["pgrep", "-a", "openvpn"])

    sections["network_interfaces"] = _run(["ip", "addr", "show"])

    sections["routing_table"] = _run(["ip", "route", "show"])

    sections["iptables_output"] = _run(
        ["iptables", "-L", "OUTPUT", "-v", "--line-numbers", "-n"])

    sections["iptables_ks_chain"] = _run(
        ["iptables", "-L", "TORVPN_KS", "-v", "-n"])

    sections["ip6tables_output"] = _run(
        ["ip6tables", "-L", "OUTPUT", "-v", "--line-numbers", "-n"])

    sections["dns_resolution"] = _run(
        ["dig", "+short", "+time=4", "check.torproject.org"])

    sections["dns_resolved_status"] = _run(
        ["systemctl", "status", "systemd-resolved", "--no-pager"])

    sections["resolv_conf"] = _run(["cat", "/etc/resolv.conf"])

    sections["tun0_stats"] = _run(["ip", "-s", "link", "show", "tun0"])

    sections["public_ip"] = _get_public_ip()

    sections["last_journal_logs"] = _run(
        ["journalctl", "-u", "tor-vpn-manager", "-n", "40",
         "--no-pager", "--output=short-precise"])

    sections["syslog_tor"] = _run(
        ["journalctl", "-u", "tor", "-n", "20", "--no-pager"])

    sections["disk_space"] = _run(["df", "-h", "/"])

    sections["memory"] = _run(["free", "-h"])

    # ── Libvirt / VMs ─────────────────────────────────────────────────────────
    sections["libvirt_bridges"] = _get_libvirt_bridges_info()

    sections["iptables_forward"] = _run(
        ["iptables", "-L", "FORWARD", "-v", "--line-numbers", "-n"])

    sections["iptables_ks_fwd"] = _run(
        ["iptables", "-L", "TORVPN_KS_FWD", "-v", "-n"])

    sections["libvirt_networks"] = _run(
        ["virsh", "net-list", "--all"])

    sections["nat_postrouting"] = _run(
        ["iptables", "-t", "nat", "-L", "POSTROUTING", "-v", "-n"])

    # ── Partage LAN (2ème carte réseau) ───────────────────────────────────────
    sections["iptables_lan_fwd"] = _run(
        ["iptables", "-L", "TORVPN_LAN_FWD", "-v", "-n"])

    sections["dnsmasq_process"] = _run(["pgrep", "-a", "dnsmasq"])

    sections["lan_interface"] = _get_lan_interface_info()

    return sections


def _get_lan_interface_info() -> str:
    config_file = Path("/etc/tor-vpn-manager/config.json")
    try:
        with open(config_file) as f:
            cfg = json.load(f)
    except Exception:
        return "(config.json illisible ou absent)"

    iface  = cfg.get("lan_iface", "")
    gw     = cfg.get("lan_gateway", "")
    subnet = cfg.get("lan_subnet", "")
    dhcp   = cfg.get("lan_dhcp", False)
    auto   = cfg.get("lan_auto", False)

    lines = [
        f"Interface configurée : {iface or '(aucune)'}",
        f"IP/passerelle       : {gw}",
        f"Sous-réseau CIDR    : {subnet}",
        f"DHCP dnsmasq        : {'oui' if dhcp else 'non'}",
        f"Auto au démarrage   : {'oui' if auto else 'non'}",
    ]
    if iface:
        lines.append("")
        lines.append(f"=== ip addr show {iface} ===")
        lines.append(_run(["ip", "addr", "show", iface], timeout=3))
        lines.append("")
        lines.append(f"=== ip route show dev {iface} ===")
        lines.append(_run(["ip", "route", "show", "dev", iface], timeout=3))
    return "\n".join(lines)


def _get_libvirt_bridges_info() -> str:
    import glob as _gl
    lines = []
    try:
        bridges = sorted(
            Path(p).name
            for p in _gl.glob("/sys/class/net/virbr*")
            if not Path(p).name.endswith("-nic")
        )
        if not bridges:
            return "Aucun bridge libvirt détecté (virbr*)"
        for br in bridges:
            ip_info = _run(["ip", "addr", "show", br], timeout=3)
            lines.append(f"=== {br} ===")
            lines.append(ip_info)
    except Exception as e:
        return f"Erreur : {e}"
    return "\n".join(lines) if lines else "Aucun bridge détecté"


def _get_public_ip() -> str:
    urls = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/7.68.0"})
            with urllib.request.urlopen(req, timeout=6) as r:
                return r.read().decode().strip()
        except Exception:
            continue
    return "(inaccessible)"


# ── Formatage du prompt ───────────────────────────────────────────────────────

def format_diag(sections: dict) -> str:
    lines = [
        "Tu es un expert Linux en réseau, VPN, Tor et sécurité système.",
        "Analyse le rapport de diagnostic ci-dessous d'un système Ubuntu/Debian",
        "qui utilise Tor-VPN Manager (OpenVPN routé via Tor avec kill switch iptables).",
        "",
        "Pour chaque problème détecté :",
        "  1. Explique brièvement le problème",
        "  2. Donne la cause probable",
        "  3. Propose une solution concrète (commandes si possible)",
        "",
        "Si tout semble normal, indique-le clairement.",
        "Réponds en français.",
        "",
        "═" * 60,
        "RAPPORT DE DIAGNOSTIC — Tor-VPN Manager",
        f"Date : {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "═" * 60,
        "",
    ]

    titles = {
        "systemd_service":      "Service systemd tor-vpn-manager",
        "tor_process":          "Processus Tor",
        "openvpn_process":      "Processus OpenVPN",
        "network_interfaces":   "Interfaces réseau (ip addr)",
        "routing_table":        "Table de routage (ip route)",
        "iptables_output":      "iptables — chaîne OUTPUT",
        "iptables_ks_chain":    "iptables — chaîne TORVPN_KS (kill switch host)",
        "ip6tables_output":     "ip6tables — chaîne OUTPUT",
        "dns_resolution":       "Résolution DNS (dig check.torproject.org)",
        "dns_resolved_status":  "systemd-resolved — statut",
        "resolv_conf":          "/etc/resolv.conf",
        "tun0_stats":           "Interface tun0",
        "public_ip":            "IP publique actuelle",
        "last_journal_logs":    "Logs journald tor-vpn-manager (40 dernières lignes)",
        "syslog_tor":           "Logs journald tor (20 dernières lignes)",
        "disk_space":           "Espace disque",
        "memory":               "Mémoire",
        "libvirt_bridges":      "Bridges libvirt/KVM (virbr*)",
        "iptables_forward":     "iptables — chaîne FORWARD (trafic VMs)",
        "iptables_ks_fwd":      "iptables — chaîne TORVPN_KS_FWD (kill switch VMs)",
        "libvirt_networks":     "Réseaux libvirt (virsh net-list)",
        "nat_postrouting":      "iptables NAT — POSTROUTING (masquerade VMs/LAN)",
        "iptables_lan_fwd":     "iptables — chaîne TORVPN_LAN_FWD (partage LAN)",
        "dnsmasq_process":      "Processus dnsmasq (DHCP partage LAN)",
        "lan_interface":        "Interface LAN — configuration et état réseau",
    }

    for key, title in titles.items():
        value = sections.get(key, "(non disponible)")
        lines += [f"── {title} ──", value, ""]

    return "\n".join(lines)


# ── Streaming Ollama ──────────────────────────────────────────────────────────

def ask_ollama_stream(prompt: str, url: str, model: str, callback) -> None:
    """
    Envoie le prompt à Ollama et appelle callback(token) pour chaque fragment reçu.
    Bloquant — à appeler depuis un thread.
    """
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": True,
    }).encode()

    req = urllib.request.Request(
        f"{url.rstrip('/')}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=120) as resp:
        for raw_line in resp:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            token = obj.get("message", {}).get("content", "")
            if token:
                callback(token)
            if obj.get("done"):
                break


# ── Entrée CLI ────────────────────────────────────────────────────────────────

def _print_stream(token: str):
    print(token, end="", flush=True)


def main():
    parser = argparse.ArgumentParser(
        prog="tor-vpn diag",
        description="Diagnostic IA pour Tor-VPN Manager (via Ollama)",
    )
    parser.add_argument("--url",   default=None,
                        help="URL du serveur Ollama (ex: http://localhost:11434)")
    parser.add_argument("--model", default=None,
                        help="Modèle Ollama (ex: llama3.3:70b)")
    parser.add_argument("--collect-only", action="store_true",
                        help="Affiche uniquement le rapport système sans IA")
    args = parser.parse_args()

    # Essaie de lire la config sauvegardée
    config_file = Path("/etc/tor-vpn-manager/config.json")
    saved = {}
    if config_file.exists():
        try:
            with open(config_file) as f:
                saved = json.load(f)
        except Exception:
            pass

    url   = args.url   or saved.get("ollama_url",   "http://localhost:11434")
    model = args.model or saved.get("ollama_model", "llama3.3:70b")

    print("═" * 60)
    print("  Tor-VPN Manager — Diagnostic IA")
    print("═" * 60)
    print()
    print("Collecte des données système …", flush=True)

    sections = collect_diag()
    print(f"  {len(sections)} sections collectées.\n")

    if args.collect_only:
        prompt = format_diag(sections)
        print(prompt)
        return

    print(f"Modèle : {model}  ({url})")
    print("Connexion à Ollama …", flush=True)

    # Vérifie la connectivité Ollama
    try:
        with urllib.request.urlopen(f"{url}/api/version", timeout=5) as r:
            ver = json.loads(r.read().decode()).get("version", "?")
        print(f"  Ollama {ver} — OK\n")
    except Exception as e:
        print(f"\n  ERREUR : impossible de joindre Ollama ({e})")
        print(f"  URL : {url}")
        print("\n  Solutions :")
        print("    1. Démarrer Ollama : ollama serve")
        print("    2. Vérifier l'URL dans l'onglet Diagnostic IA de l'interface")
        print(f"    3. Utiliser --url http://... --model {model}")
        sys.exit(1)

    prompt = format_diag(sections)

    print("═" * 60)
    print("  Analyse en cours …  (Ctrl+C pour interrompre)")
    print("═" * 60)
    print()

    try:
        ask_ollama_stream(prompt, url, model, _print_stream)
        print()
        print()
        print("═" * 60)
        print("  Diagnostic terminé.")
        print("═" * 60)
    except KeyboardInterrupt:
        print("\n\n(interrompu)")
    except Exception as e:
        print(f"\n\nErreur Ollama : {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
