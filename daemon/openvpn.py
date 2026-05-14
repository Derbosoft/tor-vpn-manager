"""
OpenVPN : gestion du processus, failover, boucle de reconnexion.

Corrections critiques appliquées :
  - --verb 3  : requis pour que net_addr_v4_add apparaisse dans les logs
  - --connect-timeout 60 : évite les faux échecs lors d'un circuit Tor lent
  - _protect_tor_routes() synchrone à net_addr_v4_add : évite la boucle de routage
  - _apply_dns_split() après "Initialization Sequence Completed" : évite que le
    script up d'OpenVPN écrase la config DNS split appliquée au démarrage
"""

import os
import subprocess
import threading
import time
from pathlib import Path

from .core import (
    _run, _deobf, AUTH_TMP, SCRIPT_DIR, RECONNECT_DELAY, RECONNECT_MAX,
)


class OpenVPNMixin:

    def _write_auth_tmp(self, username: str, password: str):
        AUTH_TMP.write_text(f"{username}\n{password}\n")
        AUTH_TMP.chmod(0o600)

    def _stop_openvpn(self):
        self._stop_vpn = True
        if self.openvpn_process and self.openvpn_process.poll() is None:
            self.openvpn_process.terminate()
        else:
            _run("pkill", "-x", "openvpn")
        if AUTH_TMP.exists():
            AUTH_TMP.unlink()

    def _get_active_creds(self):
        providers = self.config.get("providers", [])
        if not providers or self._current_provider_idx >= len(providers):
            return None
        p    = providers[self._current_provider_idx]
        ovpn = p.get("ovpn_file", "")
        if not ovpn:
            return None
        path = Path(ovpn)
        if not path.is_absolute():
            path = SCRIPT_DIR / path
        if not path.exists():
            self._log(f"[provider] Fichier .ovpn introuvable : {path}", "ERROR")
            return None
        accounts = p.get("accounts", [])
        if not accounts or self._current_account_idx >= len(accounts):
            return None
        acc = accounts[self._current_account_idx]
        return (
            str(path),
            _deobf(acc.get("u", "")),
            _deobf(acc.get("p", "")),
            p["name"],
            self._current_account_idx,
        )

    def _try_failover(self) -> bool:
        providers = self.config.get("providers", [])
        if not providers:
            return False
        cur_p    = providers[self._current_provider_idx]
        accounts = cur_p.get("accounts", [])
        if self._current_account_idx + 1 < len(accounts):
            self._current_account_idx += 1
            self._log(
                f"Failover : compte {self._current_account_idx+1}/{len(accounts)} "
                f"chez {cur_p['name']}", "WARN")
            return True
        if self._current_provider_idx + 1 < len(providers):
            self._current_provider_idx += 1
            self._current_account_idx  = 0
            next_p = providers[self._current_provider_idx]
            self._log(f"Failover : {cur_p['name']} épuisé → {next_p['name']}", "WARN")
            return True
        self._current_provider_idx = 0
        self._current_account_idx  = 0
        self._log("Failover : tous les fournisseurs et comptes épuisés.", "ERROR")
        return False

    def _openvpn_loop(self):
        self._current_provider_idx = 0
        self._current_account_idx  = 0
        self._reconnect_vpn_count  = 0
        self._stop_vpn             = False

        while not self._stop_vpn and not self._stop_flag:
            result = self._get_active_creds()
            if not result:
                self._log("Aucun fournisseur/compte disponible.", "ERROR")
                break
            cur_conf, username, password, prov_name, acc_idx = result
            self._log(f"Fournisseur : {prov_name}  (compte {acc_idx+1})", "INFO")

            if not self._check_socks_port():
                self._log("Proxy Tor inaccessible — attente (60s max) …", "WARN")
                for _ in range(60):
                    if self._stop_flag or self._stop_vpn:
                        return
                    if self._check_socks_port():
                        break
                    time.sleep(1)
            if not self._check_socks_port():
                self._log("Proxy Tor inaccessible après attente — abandon.", "ERROR")
                break
            self._log("Proxy SOCKS5 127.0.0.1:9050 OK.", "OK")

            self._orig_gw, self._orig_iface = self._get_default_gateway()
            if self._orig_gw:
                self._log(f"Passerelle : {self._orig_gw} via {self._orig_iface}")

            self._write_auth_tmp(username, password)

            route_args = self._build_route_args()
            cmd = [
                "openvpn",
                "--config",            cur_conf,
                "--auth-user-pass",    str(AUTH_TMP),
                "--script-security",   "2",
                "--verb",              "3",   # requis pour net_addr_v4_add
                "--ping",              "10",
                "--ping-exit",         "60",
                "--connect-timeout",   "60",  # Tor peut être lent à établir un circuit
                "--connect-retry",     "1",
                "--connect-retry-max", "1",
                "--socks-proxy",       "127.0.0.1", "9050",
            ]
            cmd += route_args

            if not Path("/etc/openvpn/update-resolv-conf").exists():
                self._log(
                    "/etc/openvpn/update-resolv-conf introuvable — "
                    "DNS VPN non configuré via resolvconf. "
                    "Installez : sudo apt install openvpn", "WARN")
                cmd += ["--up", "/bin/true", "--down", "/bin/true"]

            self._log(f"OpenVPN : {os.path.basename(cur_conf)} via Tor …")
            tunnel_up = False
            self._tunnel_up = False
            try:
                self.openvpn_process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

                for line in self.openvpn_process.stdout:
                    line = line.strip()
                    if not line:
                        continue
                    low = line.lower()

                    if "tun/tap device" in low and "opened" in low:
                        for word in line.split():
                            if word.startswith("tun") and word != "tun/tap":
                                self._tun_iface = word
                                self._log(f"[openvpn] Interface tunnel : {self._tun_iface}", "INFO")
                                break

                    # Synchrone — doit s'exécuter avant que le script up
                    # installe redirect-gateway.
                    elif "net_addr_v4_add" in low:
                        self._protect_tor_routes()

                    if "error" in low or "failed" in low:
                        self._log(f"[openvpn] {line}", "ERROR")
                    elif "initialization sequence completed" in low:
                        if not tunnel_up:
                            # Filet de sécurité si net_addr_v4_add a été manqué.
                            threading.Thread(
                                target=self._protect_tor_routes, daemon=True).start()
                            tunnel_up = True
                            self._tunnel_up      = True
                            self._tunnel_up_time = time.time()
                            self._reconnect_vpn_count = 0
                            self._log("Tunnel VPN actif.", "OK")
                            # Appliquer le DNS split APRÈS que le script up d'OpenVPN
                            # ait tourné, pour éviter qu'il écrase notre config.
                            self._apply_dns_split()
                            if self.config.get("kill_switch"):
                                self._killswitch_on()
                            if self.config.get("block_ipv6"):
                                self._ipv6_block_on()
                            if self.config.get("lan_auto") and self.config.get("lan_iface"):
                                self._setup_lan_sharing()
                        self._log(f"[openvpn] {line}", "OK")
                    elif "warning" in low:
                        self._log(f"[openvpn] {line}", "WARN")
                    else:
                        self._log(f"[openvpn] {line}")

                self._tunnel_up = False
                self._log("Processus OpenVPN terminé.", "WARN")

            except FileNotFoundError:
                self._log("openvpn introuvable : sudo apt install openvpn", "ERROR")
                self._killswitch_off()
                break
            except Exception as e:
                self._log(f"OpenVPN : {e}", "ERROR")
            finally:
                if AUTH_TMP.exists():
                    AUTH_TMP.unlink()

            if self._stop_vpn or self._stop_flag:
                self._killswitch_off()
                self._ipv6_block_off()
                break

            if not self.config.get("auto_reconnect", True):
                self._killswitch_off()
                self._ipv6_block_off()
                break

            if self._try_failover():
                self._log("Failover — reconnexion immédiate …", "WARN")
                time.sleep(3)
                continue

            self._reconnect_vpn_count += 1
            if self._reconnect_vpn_count > RECONNECT_MAX:
                self._log(
                    f"OpenVPN : {RECONNECT_MAX} tentatives échouées, abandon.", "ERROR")
                break

            self._log(
                f"OpenVPN : reconnexion dans {RECONNECT_DELAY}s "
                f"({self._reconnect_vpn_count}/{RECONNECT_MAX}) …", "WARN")
            for _ in range(RECONNECT_DELAY):
                if self._stop_flag or self._stop_vpn:
                    self._killswitch_off()
                    return
                time.sleep(1)
