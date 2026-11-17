#!/bin/sh
# Removes fairy-agent from this Linux machine (systemd). Undoes what install.sh / the panel's "Add host"
# command (or the by-hand steps in AGENT.md) set up:
#
#   - the services fairy-agent.service and fairy-agent-update.service (stopped first: stopping the agent runs
#     `fairy-agent fans-auto`, which hands the BMC's fans back to automatic mode, so the program is deleted
#     only AFTER the service has stopped), their files, .bak copies and drop-in folders
#   - the polkit rules /etc/polkit-1/rules.d/49-fairy-agent*.rules
#   - /etc/tmpfiles.d/fairy-agent.conf (RAPL) and /etc/udev/rules.d/60-fairy-agent-ipmi.rules (IPMI), if present
#   - the firewall rule for TCP 9101 on tailscale0 (ufw or firewalld)
#   - /usr/local/bin/fairy-agent (and .old / .new)
#   - /etc/fairy-agent (config, tokens) and /var/lib/fairy-agent, /var/lib/fairy-agent-update  (not with --keep-data)
#   - the system user and group "fairy-agent"
#
# It does not touch Tailscale, ipmitool, polkit itself, or the panel. Remove the host in the panel too.
#
# Usage (as root):   sh uninstall-fairy-agent.sh [--yes] [--keep-data]
#   --yes, -y     do not ask for confirmation (needed when not run from a terminal)
#   --keep-data   keep /etc/fairy-agent and /var/lib/fairy-agent* (config and tokens)
#
# Exit code 0: removed (or nothing to remove). 1: something could not be removed (it says what).

set -u

BIN=/usr/local/bin/fairy-agent
ETC=/etc/fairy-agent
UNITS=/etc/systemd/system
RULES=/etc/polkit-1/rules.d
USER_NAME=fairy-agent

YES=0
KEEP=0
PROBLEMS=0

say()  { printf '%s\n' "fairy: $*"; }
warn() { printf '%s\n' "fairy: PROBLEM: $*" >&2; PROBLEMS=$((PROBLEMS + 1)); }
die()  { printf '%s\n' "fairy: ERROR: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y) YES=1 ;;
    --keep-data) KEEP=1 ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) die "unknown option '$1' (use --yes and/or --keep-data)" ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || die "run it as root (sudo sh $0)"
command -v systemctl >/dev/null 2>&1 || die "this script needs systemd"

# --- what is there? ------------------------------------------------------------------------------------------

found=""
add() { found="$found
  $1"; }
# true when at least one of the given paths (or unexpanded globs, which then do not exist) exists
any_exists() { for p in "$@"; do [ -e "$p" ] && return 0; done; return 1; }

[ -e "$UNITS/fairy-agent.service" ] || systemctl cat fairy-agent.service >/dev/null 2>&1 && add "service: fairy-agent.service"
[ -e "$UNITS/fairy-agent-update.service" ] && add "service: fairy-agent-update.service"
any_exists "$UNITS"/fairy-agent*.service.bak "$UNITS"/fairy-agent*.service.d && add "unit backups / drop-ins in $UNITS"
any_exists "$RULES"/49-fairy-agent*.rules && add "polkit rules: $RULES/49-fairy-agent*.rules"
[ -e /etc/tmpfiles.d/fairy-agent.conf ] && add "/etc/tmpfiles.d/fairy-agent.conf"
[ -e /etc/udev/rules.d/60-fairy-agent-ipmi.rules ] && add "/etc/udev/rules.d/60-fairy-agent-ipmi.rules"
any_exists "$BIN" "$BIN.old" "$BIN.new" && add "program: $BIN (+ .old / .new if present)"
if [ "$KEEP" -eq 0 ]; then
  [ -e "$ETC" ] && add "$ETC  (config.yaml, tokens)"
  any_exists /var/lib/fairy-agent /var/lib/fairy-agent-update && add "/var/lib/fairy-agent, /var/lib/fairy-agent-update  (pairing, update stage)"
else
  [ -e "$ETC" ] && add "$ETC  (KEPT: --keep-data)"
fi
id "$USER_NAME" >/dev/null 2>&1 && add "system user: $USER_NAME"
getent group "$USER_NAME" >/dev/null 2>&1 && add "system group: $USER_NAME"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '9101/tcp on tailscale0'; then add "ufw rule(s): 9101/tcp on tailscale0"; fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --permanent --list-rich-rules 2>/dev/null | grep -q 'port="9101"'; then add "firewalld rich rule(s) for port 9101"; fi

if [ -z "$found" ]; then
  say "fairy-agent is not installed on this machine. Nothing to do."
  exit 0
fi

printf '%s\n' "This will remove fairy-agent from this machine:$found"
echo
if [ "$YES" -eq 0 ]; then
  [ -t 0 ] || die "not run from a terminal: add --yes to confirm"
  printf '%s' "Type YES to continue: "
  read -r ans || ans=""
  [ "$ans" = "YES" ] || { say "cancelled, nothing was changed"; exit 0; }
fi

# --- 1. stop the services (the program must still be there: stopping runs `fairy-agent fans-auto`) ---------------

if systemctl cat fairy-agent-update.service >/dev/null 2>&1; then
  say "stopping fairy-agent-update.service"
  systemctl stop fairy-agent-update.service 2>/dev/null || true
fi
if systemctl cat fairy-agent.service >/dev/null 2>&1; then
  say "stopping and disabling fairy-agent.service (the BMC's fans go back to automatic mode if fan control was on)"
  systemctl disable --now fairy-agent.service >/dev/null 2>&1 || true
  if systemctl is-active -q fairy-agent.service; then
    systemctl kill -s KILL fairy-agent.service 2>/dev/null || true
    sleep 1
    systemctl is-active -q fairy-agent.service && warn "fairy-agent.service would not stop"
  fi
fi

# --- 2. unit files, rules, tmpfiles, udev ----------------------------------------------------------------------

for f in "$UNITS/fairy-agent.service" "$UNITS/fairy-agent-update.service" \
         "$UNITS/fairy-agent.service.bak" "$UNITS/fairy-agent-update.service.bak"; do
  [ -e "$f" ] && rm -f "$f" && say "removed $f"
done
for d in "$UNITS/fairy-agent.service.d" "$UNITS/fairy-agent-update.service.d"; do
  [ -d "$d" ] && rm -rf "$d" && say "removed $d"
done
systemctl daemon-reload
systemctl reset-failed fairy-agent.service fairy-agent-update.service 2>/dev/null || true

for f in "$RULES"/49-fairy-agent*.rules; do
  [ -e "$f" ] && rm -f "$f" && say "removed $f"
done
if [ -e /etc/tmpfiles.d/fairy-agent.conf ]; then
  rm -f /etc/tmpfiles.d/fairy-agent.conf && say "removed /etc/tmpfiles.d/fairy-agent.conf"
fi
if [ -e /etc/udev/rules.d/60-fairy-agent-ipmi.rules ]; then
  rm -f /etc/udev/rules.d/60-fairy-agent-ipmi.rules && say "removed /etc/udev/rules.d/60-fairy-agent-ipmi.rules"
  command -v udevadm >/dev/null 2>&1 && udevadm control --reload 2>/dev/null || true
fi

# --- 3. firewall (only the rule for the panel's port on the Tailscale interface) -----------------------------

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  ufw status 2>/dev/null | awk '$1 == "9101/tcp" && $2 == "on" && $3 == "tailscale0" && $4 == "ALLOW" && $0 !~ /\(v6\)/ { print $NF }' |
  while read -r src; do
    case "$src" in ''|*[!0-9.]*) continue ;; esac
    if ufw --force delete allow in on tailscale0 from "$src" to any port 9101 proto tcp >/dev/null 2>&1; then
      say "ufw: removed the rule for $src -> 9101/tcp on tailscale0"
    else
      say "ufw: could not remove the rule for $src (remove it with: ufw status numbered, then ufw delete N)"
    fi
  done
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --permanent --list-rich-rules 2>/dev/null | grep 'port="9101"' |
  while IFS= read -r r; do
    firewall-cmd -q --permanent --remove-rich-rule="$r" && say "firewalld: removed: $r"
  done
  firewall-cmd -q --reload 2>/dev/null || true
fi

# --- 4. program, data ------------------------------------------------------------------------------------------

for f in "$BIN" "$BIN.old" "$BIN.new"; do
  [ -e "$f" ] && rm -f "$f" && say "removed $f"
done
if [ "$KEEP" -eq 0 ]; then
  for d in "$ETC" /var/lib/fairy-agent /var/lib/fairy-agent-update; do
    [ -e "$d" ] && rm -rf "$d" && say "removed $d"
  done
else
  say "kept $ETC (--keep-data); it holds this machine's tokens: delete it when you no longer need it"
fi

# --- 5. the user and its group ---------------------------------------------------------------------------------

if id "$USER_NAME" >/dev/null 2>&1; then
  if ! userdel "$USER_NAME" 2>/dev/null; then
    pkill -KILL -u "$USER_NAME" 2>/dev/null || true
    sleep 1
    userdel "$USER_NAME" 2>/dev/null || warn "could not delete the user $USER_NAME (is a process of it still running? try: userdel $USER_NAME)"
  fi
  id "$USER_NAME" >/dev/null 2>&1 || say "removed user $USER_NAME"
fi
if getent group "$USER_NAME" >/dev/null 2>&1; then
  if groupdel "$USER_NAME" 2>/dev/null; then
    say "removed group $USER_NAME"
  else
    warn "could not delete the group $USER_NAME (is it still somebody's primary group?)"
  fi
fi

# --- summary ----------------------------------------------------------------------------------------------------

echo
if [ "$PROBLEMS" -eq 0 ]; then
  say "fairy-agent has been removed from this machine."
else
  say "finished with $PROBLEMS problem(s), listed above."
fi
echo
echo "Still to do, by hand:"
echo "  - In the panel: open this host and press \"Remove host\" (the panel keeps its own copy of the tokens)."
if command -v pveum >/dev/null 2>&1 && pveum user list 2>/dev/null | grep -q 'fairy@pve'; then
  echo "  - This is a Proxmox node: Add host made a read-only API token for the panel. Remove it with:"
  echo "        pveum user token remove fairy@pve panel-<this node's name>"
  echo "    and, if you want the read-only user gone too:  pveum user delete fairy@pve"
fi
echo "  - If the agent read a Home Assistant plug: delete the long-lived token it used in Home Assistant (profile > Security)."
echo "  - If the agent's config used an env_file or ca_file outside $ETC, those files were not touched."

[ "$PROBLEMS" -eq 0 ] || exit 1
exit 0
