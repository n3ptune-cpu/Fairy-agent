#!/bin/sh
# Fairy agent installer for Linux (systemd), the machine side of the panel's "Add host":
#
#   curl -fsSL https://github.com/n3ptune-cpu/Fairy-agent/releases/latest/download/install.sh | sudo sh -s -- \
#     --join CODE --panel 100.x.y.z [--power-control] [--self-update] [--wol] [--ups] [--ups-name NAME] [--ipmi]
#     [--proxmox]
#
# It downloads the latest release (binary, SHA256SUMS + signature, the systemd units and rules), checks every
# file against SHA256SUMS and the signature with fairy-agent's built-in release key, then installs exactly what
# AGENT.md describes: user fairy-agent, /usr/local/bin/fairy-agent, /etc/fairy-agent (config.yaml and tokens
# 0640 root:fairy-agent), fairy-agent.service (+ fairy-agent-update.service and the polkit rule when needed,
# the RAPL tmpfiles rule when the machine has RAPL), a firewall rule for the panel when ufw / firewalld is on.
# `fairy-agent join` then writes the tokens and the chosen settings (no editor, nothing to copy) and stores the
# one-time join code; the panel picks the tokens up by itself within a few seconds. With --proxmox (a standalone
# Proxmox VE node), join also makes the panel a read-only API token (user fairy@pve, role PVEAuditor, token
# fairy@pve!panel-<node>) that the panel picks up once with the agent's tokens; nothing to copy.
#
# Safe to run again (with a new code from the panel's "Re-pair"): settings are kept, the tokens are replaced
# by new ones (the panel gets them by pairing), the binary and
# units are brought up to date. Nothing secret is printed.
set -eu

REPO="${FAIRY_REPO:-n3ptune-cpu/Fairy-agent}"
BASE="${FAIRY_RELEASE_URL:-https://github.com/$REPO/releases/latest/download}"
BIN=/usr/local/bin/fairy-agent
ETC=/etc/fairy-agent
UNITS=/etc/systemd/system

say() { printf '%s\n' "fairy: $*"; }
die() { printf '%s\n' "fairy: ERROR: $*" >&2; exit 1; }

CODE="" PANEL="" UPSNAME=""
POWER=0 UPDATE=0 WOL=0 UPS=0 IPMI=0 PVE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --join) [ $# -ge 2 ] || die "--join needs the code"; CODE="$2"; shift ;;
    --panel) [ $# -ge 2 ] || die "--panel needs the panel's Tailscale address"; PANEL="$2"; shift ;;
    --power-control) POWER=1 ;;
    --self-update) UPDATE=1 ;;
    --wol) WOL=1 ;;
    --ups) UPS=1 ;;
    --ups-name) [ $# -ge 2 ] || die "--ups-name needs a name"; UPS=1; UPSNAME="$2"; shift ;;
    --ups=*) UPS=1; UPSNAME="${1#--ups=}" ;;
    --ipmi) IPMI=1 ;;
    --proxmox) PVE=1 ;;
    -h|--help) sed -n '2,20p' "$0" 2>/dev/null || true; exit 0 ;;
    *) die "unknown option $1 (copy the whole command from the panel's Add host dialog)" ;;
  esac
  shift
done
[ -n "$CODE" ] && [ -n "$PANEL" ] || die "usage: install.sh --join CODE --panel PANEL_TAILSCALE_IP [options]"
case "$PANEL" in *[!0-9.]*) die "--panel must be the panel's Tailscale IPv4 address, e.g. 100.88.109.47" ;; esac
[ "$(id -u)" -eq 0 ] || die "run it as root (… | sudo sh -s -- …)"
command -v systemctl >/dev/null 2>&1 || die "this installer needs systemd"
command -v curl >/dev/null 2>&1 || die "curl is missing"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is missing (coreutils)"

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported CPU $(uname -m) (releases exist for amd64 and arm64)" ;;
esac
ASSET="fairy-agent-linux-$ARCH"

TMP="$(mktemp -d /tmp/fairy-install.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT INT TERM

say "downloading the latest release from $BASE"
FILES="$ASSET SHA256SUMS SHA256SUMS.sig VERSION fairy-agent.service fairy-agent-update.service fairy-agent.polkit.rules fairy-agent.tmpfiles.conf"
for f in $FILES; do
  curl -fsSL --proto '=https,file' --proto-redir '=https' --retry 3 -o "$TMP/$f" "$BASE/$f" || die "download of $f failed"
done

# 1. every file must be listed in SHA256SUMS with the same SHA-256
for f in $FILES; do
  case "$f" in SHA256SUMS|SHA256SUMS.sig) continue ;; esac
  want="$(awk -v n="$f" '$2 == n || $2 == "*" n { print $1 }' "$TMP/SHA256SUMS")"
  [ -n "$want" ] || die "$f is not listed in SHA256SUMS"
  got="$(sha256sum "$TMP/$f" | awk '{ print $1 }')"
  [ "$want" = "$got" ] || die "$f does not match SHA256SUMS (corrupted or tampered download)"
done
chmod 0755 "$TMP/$ASSET"

# 2. the signature of SHA256SUMS, with the release key built into fairy-agent: the installed binary's when it
#    can (a re-run), else the new one's (a first install trusts GitHub's HTTPS, as any first download does)
rc=2
if [ -x "$BIN" ]; then
  "$BIN" verify-release "$TMP" >/dev/null 2>&1 && rc=0 || rc=$?
  [ "$rc" -eq 1 ] && die "the release signature does not match the installed fairy-agent's release key"
fi
if [ "$rc" -ne 0 ]; then
  "$TMP/$ASSET" verify-release "$TMP" >/dev/null 2>&1 && rc=0 || rc=$?
fi
case "$rc" in
  0) say "release $(cat "$TMP/VERSION") verified (SHA256SUMS signature and hashes)" ;;
  3) say "WARNING: this build has no release key, the signature was not checked (hashes only)" ;;
  *) die "the release signature check failed" ;;
esac

# 3. user, program, folders (AGENT.md, "Install on Linux")
if ! id fairy-agent >/dev/null 2>&1; then
  nologin="$(command -v nologin 2>/dev/null || echo /usr/sbin/nologin)"
  useradd --system --no-create-home --shell "$nologin" fairy-agent
  say "created the system user fairy-agent"
fi
install -m 0755 "$TMP/$ASSET" "$BIN.new"
mv -f "$BIN.new" "$BIN"
command -v restorecon >/dev/null 2>&1 && restorecon "$BIN" || true
install -d -m 0750 -o root -g fairy-agent "$ETC"
install -d -m 0700 -o fairy-agent -g fairy-agent /var/lib/fairy-agent

# 4. units and rules (an existing unit that differs is kept as .bak)
put() { # put SRC DEST MODE
  if [ -f "$2" ] && ! cmp -s "$1" "$2"; then cp -p "$2" "$2.bak"; say "kept your previous $2 as $2.bak"; fi
  install -m "$3" "$1" "$2"
}
put "$TMP/fairy-agent.service" "$UNITS/fairy-agent.service" 0644
if [ "$UPDATE" -eq 1 ] || [ -f "$UNITS/fairy-agent-update.service" ]; then
  put "$TMP/fairy-agent-update.service" "$UNITS/fairy-agent-update.service" 0644
fi
if [ "$POWER" -eq 1 ] || [ "$UPDATE" -eq 1 ]; then
  if [ ! -d /etc/polkit-1/rules.d ]; then
    if command -v apt-get >/dev/null 2>&1; then
      say "installing polkitd (needed for shutdown / reboot and self-update)"
      DEBIAN_FRONTEND=noninteractive apt-get install -y -q polkitd >/dev/null || apt-get install -y -q policykit-1 >/dev/null
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y -q polkit >/dev/null
    fi
  fi
  [ -d /etc/polkit-1/rules.d ] || die "polkit is not installed (needed for shutdown / reboot and self-update)"
  put "$TMP/fairy-agent.polkit.rules" /etc/polkit-1/rules.d/49-fairy-agent.rules 0644
fi
if ls /sys/class/powercap/intel-rapl:*/energy_uj >/dev/null 2>&1; then
  put "$TMP/fairy-agent.tmpfiles.conf" /etc/tmpfiles.d/fairy-agent.conf 0644
  systemd-tmpfiles --create /etc/tmpfiles.d/fairy-agent.conf || true
fi

# 5. firewall: only the panel, only on the Tailscale interface
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "^Status: active"; then
  ufw allow in on tailscale0 from "$PANEL" to any port 9101 proto tcp >/dev/null && say "ufw: allowed $PANEL to port 9101 on tailscale0"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  rule="rule family=ipv4 source address=$PANEL/32 port port=9101 protocol=tcp accept"
  firewall-cmd -q --permanent --add-rich-rule="$rule" && firewall-cmd -q --reload && say "firewalld: allowed $PANEL to port 9101"
fi

# 6. tokens, settings and the join code (fairy-agent join prints no secret)
set -- --code "$CODE" --panel "$PANEL"
[ "$POWER" -eq 1 ] && set -- "$@" --power-control
[ "$UPDATE" -eq 1 ] && set -- "$@" --self-update
[ "$WOL" -eq 1 ] && set -- "$@" --wol
[ "$IPMI" -eq 1 ] && set -- "$@" --ipmi
[ "$PVE" -eq 1 ] && set -- "$@" --proxmox
if [ "$UPS" -eq 1 ]; then
  if [ -n "$UPSNAME" ]; then set -- "$@" --ups-name "$UPSNAME"; else set -- "$@" --ups; fi
fi
"$BIN" join "$@"

systemctl daemon-reload
systemctl enable -q fairy-agent
systemctl restart fairy-agent
say "fairy-agent $(awk '{ print $2 }' "$TMP/VERSION") started; waiting for the panel to pair (keep the Add host dialog open) ..."

# 7. wait (up to 2 minutes) until the panel has picked up the tokens
i=0
while [ $i -lt 60 ]; do
  if "$BIN" pair-status >/dev/null 2>&1; then
    say "paired with the panel. The host appears there within a few seconds. Done."
    exit 0
  fi
  if ! systemctl is-active -q fairy-agent; then
    journalctl -u fairy-agent -n 15 --no-pager 2>/dev/null || true
    die "fairy-agent is not running (see above)"
  fi
  sleep 2
  i=$((i + 1))
done
say "not paired yet: $("$BIN" pair-status 2>&1 || true)"
say "the panel keeps trying while the code is valid; check: fairy-agent pair-status, journalctl -u fairy-agent"
