#!/bin/bash
set -euo pipefail

read -p "Nom de l'utilisateur (ex: user1) : " USER
ADMIN="adm_${USER}"
NOSSHGROUP="nossh"

# 0) Groupe nossh (si absent)
getent group "$NOSSHGROUP" >/dev/null || groupadd "$NOSSHGROUP"

# 1) Utilisateur standard
if ! id -u "$USER" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" "$USER"
fi

# 2) Clé RSA 8192 pour $USER (si absente)
USER_HOME=$(eval echo "~$USER")
SSH_DIR="$USER_HOME/.ssh"
mkdir -p "$SSH_DIR"; chown "$USER:$USER" "$SSH_DIR"; chmod 700 "$SSH_DIR"
if [ ! -f "$SSH_DIR/id_rsa" ]; then
  sudo -u "$USER" ssh-keygen -t rsa -b 8192 -f "$SSH_DIR/id_rsa" -N ""
  cp "$SSH_DIR/id_rsa.pub" "$SSH_DIR/authorized_keys"
  chown "$USER:$USER" "$SSH_DIR/authorized_keys"
  chmod 600 "$SSH_DIR/authorized_keys"
fi

# 3) Compte admin lié
if ! id -u "$ADMIN" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "Admin for $USER" "$ADMIN" --no-create-home
  usermod -aG "$NOSSHGROUP" "$ADMIN"   # adm.userX dans nossh (SSH interdit)
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
# ajoute "AllowUsers USER" s'il n'existe pas déjà (mot entier)
if ! grep -Eq "^[[:space:]]*AllowUsers[[:space:]].*\b${USER}\b" "$ALLOWFILE"; then
  echo "AllowUsers ${USER}" >> "$ALLOWFILE"
fi

# Valide conf SSH puis reload (sans casser la session)
if sshd -t 2>/dev/null; then
  systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
else
  echo "⚠️ Validation sshd a échoué. Le fichier ${ALLOWFILE} n'a PAS été rechargé."
fi

# --- Résumé & aide connexion ---
echo "---------------------------------------------------------"
echo "✅ Utilisateur $USER créé (+ clé RSA 8192)."
echo "   - Privée : $SSH_DIR/id_rsa"
echo "   - Publique : $SSH_DIR/id_rsa.pub"
echo "✅ Compte admin $ADMIN créé, ajouté à '$NOSSHGROUP'."
echo "   -> accessible uniquement via : sudo -u $ADMIN -i"
echo "✅ SSH AllowUsers mis à jour (drop-in) pour inclure: $USER"
echo ""
echo "🔗 Connexion SSH :"
echo "  [Linux/macOS]"
echo "    ssh -i ~/.ssh/id_rsa $USER@IP_DU_SERVEUR"
echo ""
echo "  [Windows - PowerShell/OpenSSH]"
echo "    ssh -i C:\\Users\\VOTRE_NOM\\.ssh\\id_rsa $USER@IP_DU_SERVEUR"
echo ""
echo "  [Windows - PuTTY]"
echo "    1) PuTTYgen: charger id_rsa -> Save private key (.ppk)"
echo "    2) PuTTY: Host=IP_DU_SERVEUR, Auth=charger id_rsa.ppk"
echo "---------------------------------------------------------"
