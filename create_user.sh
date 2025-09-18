#!/bin/bash
set -euo pipefail

read -p "Nom de l'utilisateur (ex: user1) : " USER
read -s -p "Passphrase pour la clé RSA de ${USER} : " PHRASEKEY
echo
ADMIN="adm_${USER}"
NOSSHGROUP="nossh"

# 0) Groupe nossh (si absent)
getent group "$NOSSHGROUP" >/dev/null || groupadd "$NOSSHGROUP"

# 1) Utilisateur standard
if ! id -u "$USER" >/div/null 2>&1; then
  adduser --disabled-password --gecos "" "$USER"
fi

# 2) Clé RSA 8192 pour $USER (avec passphrase) + authorized_keys
USER_HOME=$(eval echo "~$USER")
SSH_DIR="$USER_HOME/.ssh"
mkdir -p "$SSH_DIR"; chown "$USER:$USER" "$SSH_DIR"; chmod 700 "$SSH_DIR"

if [ ! -f "$SSH_DIR/id_rsa" ]; then
  sudo -u "$USER" ssh-keygen -t rsa -b 8192 -f "$SSH_DIR/id_rsa" -N "$PHRASEKEY"
fi

# Ajout clé publique à authorized_keys (anti-doublon)
PUBKEY_FILE="$SSH_DIR/id_rsa.pub"
PUBKEY=$(cat "$PUBKEY_FILE")
grep -qxF "$PUBKEY" "$SSH_DIR/authorized_keys" 2>/dev/null || echo "$PUBKEY" >> "$SSH_DIR/authorized_keys"
chown "$USER:$USER" "$SSH_DIR/authorized_keys"
chmod 600 "$SSH_DIR/authorized_keys"

# 3) Compte admin lié
if ! id -u "$ADMIN" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "Admin for $USER" "$ADMIN" --no-create-home
  usermod -aG "$NOSSHGROUP" "$ADMIN"   # SSH interdit via DenyGroups nossh
  passwd -l "$ADMIN"                   # pas d'auth par mot de passe
fi

# 4) Sudoers : seul $USER -> $ADMIN (auth requise)
SUDOFILE="/etc/sudoers.d/10-${USER}-to-${ADMIN}"
cat > "$SUDOFILE" <<EOF
# ${USER} peut agir en tant que ${ADMIN} (auth sudo requise)
${USER} ALL=(${ADMIN}) ALL
EOF
chmod 440 "$SUDOFILE"

# 5) Protection : empêcher %sudo d'endosser ${ADMIN}
PROTECTFILE="/etc/sudoers.d/90-protect-${ADMIN}"
cat > "$PROTECTFILE" <<EOF
%sudo ALL=(ALL, !${ADMIN}) ALL
EOF
chmod 440 "$PROTECTFILE"

# 6) SSH AllowUsers (incrémental, drop-in)
mkdir -p /etc/ssh/sshd_config.d
ALLOWFILE="/etc/ssh/sshd_config.d/10-allow-users.conf"
touch "$ALLOWFILE"
if ! grep -Eq "^[[:space:]]*AllowUsers[[:space:]].*\b${USER}\b" "$ALLOWFILE"; then
  echo "AllowUsers ${USER}" >> "$ALLOWFILE"
fi

# Valide conf SSH puis reload (sans casser la session)
if sshd -t 2>/dev/null; then
  systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
else
  echo "⚠️ Validation sshd a échoué. Le fichier ${ALLOWFILE} n'a PAS été rechargé."
fi

# --- Affichage clé publique & empreinte ---
FPR=$(ssh-keygen -lf "$PUBKEY_FILE" | awk '{print $2" ("$4")"}')

echo "---------------------------------------------------------"
echo "✅ Utilisateur $USER créé (+ clé RSA 8192 avec passphrase)."
echo "   - Privée  : $SSH_DIR/id_rsa"
echo "   - Publique: $SSH_DIR/id_rsa.pub ("
echo "🔐 Empreinte de la clé publique : $FPR"
echo ""
echo "📋 Clé publique (a integrer dans authorizedkey du serveur cible) :"
echo "$PUBKEY"
echo "---------------------------------------------------------"
echo "✅ Compte admin $ADMIN créé, ajouté à '$NOSSHGROUP'."
echo "   -> accessible uniquement via : sudo -u $ADMIN -i"
echo "✅ SSH AllowUsers mis à jour pour inclure: $USER"
echo ""
echo "🔗 Connexion SSH :"
echo "  [Linux/macOS]               : ssh -i ~/.ssh/id_rsa $USER@IP_DU_SERVEUR"
echo "  [Windows - PowerShell]      : ssh -i C:\\Users\\VOTRE_NOM\\.ssh\\id_rsa $USER@IP_DU_SERVEUR"
echo "  [Windows - PuTTY]           : PuTTYgen -> charger id_rsa -> entrer passphrase -> Save .ppk -> PuTTY"
echo "---------------------------------------------------------"
