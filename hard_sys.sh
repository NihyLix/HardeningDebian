#!/bin/bash
# Proxmox Hardening (SSH + Mail alerts + Fail2ban + PVE firewall)
# NihyLix style – clair, concis, idempotent.
set -euo pipefail

# ====== PARAMS (prompts) ======
read -rp "Réseau d'admin autorisé (CIDR, ex: 10.10.10.0/24) : " ADMIN_NET
read -rp "Email destinataire des alertes SSH : " ALERT_EMAIL
: "${ADMIN_NET:?CIDR requis}"
: "${ALERT_EMAIL:?Email requis}"

# ====== Paths / const ======
ALLOWFILE="/etc/ssh/sshd_config.d/10-allow-users.conf"
HARDENFILE="/etc/ssh/sshd_config.d/60-hardening.conf"
BANNER="/etc/issue.net"
NOSSHGROUP="nossh"
MAILER_SCRIPT="/usr/local/sbin/ssh-log-mailer.sh"
RSYSLOG_DROPIN="/etc/rsyslog.d/50-sshd-mail.conf"
SSH_ALERT_EMAIL_FILE="/etc/ssh/ssh-alert-email"
STRICT_CRYPTO=1  # 0 si clients anciens
PVE_CLUSTER_FW="/etc/pve/firewall/cluster.fw"

# ====== Pre-reqs ======
command -v sshd >/dev/null || { apt update -y && apt install -y openssh-server; }
apt update -y
apt install -y rsyslog bsd-mailx fail2ban

# ====== Groupe qui bloque SSH pour comptes admin liés ======
getent group "$NOSSHGROUP" >/dev/null || groupadd "$NOSSHGROUP"

# ====== SSH: AllowUsers drop-in (éviter lockout) ======
mkdir -p /etc/ssh/sshd_config.d
touch "$ALLOWFILE"; chmod 644 "$ALLOWFILE"
if ! grep -Eq '^[[:space:]]*AllowUsers[[:space:]]+' "$ALLOWFILE"; then
  if [ -n "${SUDO_USER:-}" ] && id "${SUDO_USER}" &>/dev/null; then
    echo "AllowUsers ${SUDO_USER}" >> "$ALLOWFILE"
    echo "→ Ajout de ${SUDO_USER} à AllowUsers (prévention lockout)."
  else
    echo "⚠️  $ALLOWFILE est vide : ajoute au moins un compte autorisé avant reload."
  fi
fi

# ====== SSH: Hardening drop-in ======
cat > "$HARDENFILE" <<'EOF'
# --- Journalisation & protocole ---
LogLevel VERBOSE
Protocol 2

# --- AuthN : clés uniquement ---
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
UsePAM yes

# --- Comptes & groupes ---
PermitRootLogin no
DenyGroups nossh

# --- Réductions de surface ---
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
GatewayPorts no
PermitTunnel no

# --- Tolérance & timeouts ---
MaxAuthTries 3
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2
MaxSessions 10

# --- Bannière ---
Banner /etc/issue.net
EOF

if [ "$STRICT_CRYPTO" -eq 1 ]; then
  cat >> "$HARDENFILE" <<'EOF'

# --- Crypto moderne (commentez si vieux clients) ---
KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256
PubkeyAcceptedKeyTypes ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256
EOF
fi
chmod 644 "$HARDENFILE"

# ====== Bannière ======
[ -s "$BANNER" ] || { echo "[ ACCES RESERVE ] Connexions journalisées." > "$BANNER"; chmod 644 "$BANNER"; }

# ====== Valider & recharger SSH ======
sshd -t
systemctl reload sshd 2>/dev/null || systemctl reload ssh

# ====== Alertes e-mail à chaque tentative SSH ======
echo "$ALERT_EMAIL" > "$SSH_ALERT_EMAIL_FILE"
chmod 640 "$SSH_ALERT_EMAIL_FILE"

cat > "$MAILER_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ALERT_EMAIL_FILE="/etc/ssh/ssh-alert-email"
[ -f "$ALERT_EMAIL_FILE" ] || exit 0
TO="$(cat "$ALERT_EMAIL_FILE")"
read -r LINE || exit 0
# Filtrage des événements sshd pertinents
if echo "$LINE" | grep -Eq 'sshd'; then
  if echo "$LINE" | grep -Eq 'Accepted|Failed|Invalid user|authentication failure|Disconnected from invalid'; then
    HOST="$(hostname -f 2>/dev/null || hostname)"
    SUBJ="[SSH] $(echo "$LINE" | sed -E 's/.*sshd\[[0-9]+\]: //' | cut -c1-80)"
    {
      echo "Host : $HOST"
      echo "When : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
      echo "Raw  : $LINE"
    } | mail -s "$SUBJ" "$TO" || true
  fi
fi
EOF
chmod 750 "$MAILER_SCRIPT"

cat > "$RSYSLOG_DROPIN" <<EOF
# Mail chaque événement sshd pertinent -> $ALERT_EMAIL
if (\$programname == "sshd") then {
  action(type="omprog" binary="$MAILER_SCRIPT")
}
EOF
systemctl enable rsyslog >/dev/null 2>&1 || true
systemctl restart rsyslog

# ====== Fail2ban (sshd) ======
install -d -m 755 /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled  = true
port     = ssh
logpath  = /var/log/auth.log
backend  = systemd
maxretry = 4
findtime = 10m
bantime  = 2h
EOF
systemctl restart fail2ban || true

# ====== Pare-feu Proxmox (datacenter) ======
# ATTENTION: vérifie ADMIN_NET, sinon risque de lockout.
install -d -m 755 /etc/pve/firewall || true
if [ ! -f "$PVE_CLUSTER_FW" ]; then
  cat > "$PVE_CLUSTER_FW" <<EOF
[OPTIONS]
policy_in: DROP
enable: 1

[RULES]
IN ACCEPT -p tcp -dport 22   -source $ADMIN_NET
IN ACCEPT -p tcp -dport 8006 -source $ADMIN_NET
# Autorise le trafic établi
IN ACCEPT -p all -conntrack ESTABLISHED,RELATED
EOF
else
  # Ajoute/Met à jour les règles idempotemment
  grep -q "enable:" "$PVE_CLUSTER_FW" || sed -i '1i[OPTIONS]\nenable: 1\n' "$PVE_CLUSTER_FW"
  grep -q "policy_in:" "$PVE_CLUSTER_FW" || sed -i '2ipolicy_in: DROP' "$PVE_CLUSTER_FW"
  grep -q "IN ACCEPT -p tcp -dport 22   -source $ADMIN_NET" "$PVE_CLUSTER_FW" || \
    echo "IN ACCEPT -p tcp -dport 22   -source $ADMIN_NET" >> "$PVE_CLUSTER_FW"
  grep -q "IN ACCEPT -p tcp -dport 8006 -source $ADMIN_NET" "$PVE_CLUSTER_FW" || \
    echo "IN ACCEPT -p tcp -dport 8006 -source $ADMIN_NET" >> "$PVE_CLUSTER_FW"
  grep -q "IN ACCEPT -p all -conntrack ESTABLISHED,RELATED" "$PVE_CLUSTER_FW" || \
    echo "IN ACCEPT -p all -conntrack ESTABLISHED,RELATED" >> "$PVE_CLUSTER_FW"
fi

# Redémarrer le firewall PVE
pve-firewall restart || true

# ====== Résumé ======
echo "---------------------------------------------------------"
echo "✅ SSH durci : clés uniquement, DenyGroups=${NOSSHGROUP}, timeouts, LogLevel=VERBOSE"
echo "   Drop-ins :"
echo "     - $ALLOWFILE (liste des comptes autorisés)"
echo "     - $HARDENFILE (paramètres de durcissement)"
echo "✅ Alertes e-mail SSH actives -> $ALERT_EMAIL"
echo "   - Script : $MAILER_SCRIPT"
echo "   - Rsyslog: $RSYSLOG_DROPIN (sans 'stop' -> compatible Fail2ban)"
echo "✅ Fail2ban actif pour sshd"
echo "✅ PVE firewall : 22/8006 autorisés depuis $ADMIN_NET ; policy_in=DROP ; enable=1"
echo "---------------------------------------------------------"
echo "👉 Ajoute tes comptes SSH autorisés :"
echo "   echo 'AllowUsers user1' >> $ALLOWFILE && systemctl reload sshd"
echo "👉 Bloque les comptes admin liés via groupe '$NOSSHGROUP' (ex: adm_user1) :"
echo "   usermod -aG $NOSSHGROUP adm_user1"
echo "👉 Vérifs rapides :"
echo "   sshd -T | grep -E 'allowusers|denygroups|pubkeyauthentication|passwordauthentication'"
echo "   systemctl status rsyslog fail2ban pve-firewall --no-pager"
echo "   grep -E 'AllowUsers' $ALLOWFILE"
echo "---------------------------------------------------------"
