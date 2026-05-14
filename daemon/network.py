"""
Réseau : gateway, SOCKS, routes Tor, routes exclues.
"""

import ipaddress
import socket

from .core import _run, TOR_ROUTES_FILE


class NetworkMixin:

    def _get_default_gateway(self):
        try:
            r = _run("ip", "route", "show", "default")
            for line in r.stdout.decode().splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0] == "default" and parts[1] == "via":
                    return parts[2], parts[4]
        except Exception:
            pass
        return None, None

    def _check_socks_port(self) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", 9050), timeout=3):
                return True
        except OSError:
            return False

    def _build_route_args(self) -> list:
        args = []
        for entry in self.config.get("excluded_ips", []):
            try:
                net = ipaddress.ip_network(entry, strict=False)
                args += ["--route", str(net.network_address), str(net.netmask), "net_gateway"]
            except ValueError:
                self._log(f"Route ignorée (invalide) : {entry}", "WARN")
        return args

    def _protect_tor_routes(self):
        """Ajoute des routes /32 statiques via la gateway originale pour chaque
        IP de guard Tor active.  Appel SYNCHRONE depuis le thread stdout
        d'OpenVPN, avant que redirect-gateway ne soit installé par le script up."""
        if not self._orig_gw or not self.tor_process:
            return
        pid = self.tor_process.pid
        try:
            r = _run("ss", "-tnp", "state", "established")
            added = set()
            for line in r.stdout.decode().splitlines():
                if f"pid={pid}" not in line:
                    continue
                for part in line.split():
                    if ":" not in part:
                        continue
                    ip = part.rsplit(":", 1)[0]
                    if ip.startswith("127.") or ip.startswith("0."):
                        continue
                    try:
                        ipaddress.ip_address(ip)
                    except ValueError:
                        continue
                    if ip not in added:
                        _run("ip", "route", "replace", f"{ip}/32",
                             "via", self._orig_gw, "dev", self._orig_iface)
                        added.add(ip)
                        self._protected_routes.add(ip)
            if added:
                self._log(f"[route] {len(added)} IP(s) Tor protégée(s).", "INFO")
                try:
                    TOR_ROUTES_FILE.write_text(
                        "\n".join(self._protected_routes) + "\n")
                except Exception:
                    pass
        except Exception as e:
            self._log(f"[route] {e}", "WARN")

    def _cleanup_tor_routes(self):
        """Supprime les routes /32 Tor (session courante + fichier persistant)."""
        routes = set(self._protected_routes)
        if TOR_ROUTES_FILE.exists():
            try:
                routes.update(
                    ln.strip()
                    for ln in TOR_ROUTES_FILE.read_text().splitlines()
                    if ln.strip()
                )
            except Exception:
                pass
        for ip in routes:
            _run("ip", "route", "del", f"{ip}/32")
        self._protected_routes.clear()
        TOR_ROUTES_FILE.unlink(missing_ok=True)
        if routes:
            self._log(f"[route] {len(routes)} route(s) /32 Tor supprimée(s).", "INFO")
