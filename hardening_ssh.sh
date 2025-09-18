#!/bin/bash
# Hardening SSH "ANSSI-like" avec drop-ins
# - AllowUsers dans /etc/ssh/sshd_config.d/10-allow-users.conf
# - DenyGroups nossh (pour bloquer les comptes admin liés)
# - Auth par clé uniquement ; PAM conservé (account/session)
# - Crypto moderne optionnelle
set -euo pipefail

ALLOWFILE="/etc/ssh/sshd_config.d/10-allow-users.conf"
HARDENFILE="/etc/ssh/sshd_config.d/60-hardening.conf"
BANNER="/etc/issue.net"
STRICT_CRYPTO=1   # 1 = active les listes Kex/Ciphers/MACs strictes ; 0 = laisser défaut OpenSSH

# 0) OpenSSH serveur + groupe nossh
command -v sshd >/dev/null || { apt update -y && apt install -y openssh-server; }
getent group nossh >/dev/null || groupadd nossh

# 1) Banner (si absente)
[ -s "$BANNER" ] || { echo "[ ACCES RESERVE ] Connexions journalisées." > "$BANNER"; chmod 644 "$BANNER"; }

# 2) Drop-in AllowUsers (prévention lockout)
mkdir -p /etc/ssh/sshd_config.d
touch "$ALLOWFILE"; chmod 644 "$ALLOWFILE"
if ! grep -Eq '^[[:space:]]*AllowUsers[[:space:]]+' "$ALLOWFILE"; then
  if [ -n "${SUDO_USER:-}" ] && id "${SUDO_USER}" &>/dev/null; then
    echo "AllowUsers ${SUDO_USER}" >> "$ALLOWFILE"
    echo "→ Ajout de ${SUDO_USER} à AllowUsers (évite le lockout initial)."
  else
    echo "⚠️  $ALLOWFILE est vide : ajoute au moins un compte 'AllowUsers userX' avant reload."
  fi
fi

# 3) Drop-in de durcissement
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

# 4) Crypto moderne (désactivez si clients anciens)
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

# 5) Validation & reload
sshd -t
systemctl reload sshd 2>/dev/null || systemctl reload ssh

echo "---------------------------------------------------------"
echo "✅ Hardening SSH appliqué."
echo "   - AllowUsers : $ALLOWFILE   (ajoute tes comptes autorisés ici)"
echo "   - Hardening  : $HARDENFILE  (clés uniquement, DenyGroups nossh, timeouts)"
echo "   - Banner     : $BANNER"
echo "   - Crypto     : STRICT_CRYPTO=$STRICT_CRYPTO"
echo ""
echo "➕ Ajouter un compte autorisé :"
echo "   echo 'AllowUsers user1' >> $ALLOWFILE && systemctl reload sshd"
echo "🛑 Bloquer les comptes admin liés (ex: adm_user1) :"
echo "   usermod -aG nossh adm_user1"
echo "---------------------------------------------------------"
