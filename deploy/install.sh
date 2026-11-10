#!/bin/sh
# Fairy agent installer for Linux (systemd), the machine side of the panel's "Add host".
#
# Use the command from the panel's Add host (or Re-pair) dialog. It names one checked release, refuses to run
# this script unless its SHA-256 is the one the panel verified, and passes the release's fingerprint and the
# one-time join code. There is no "latest" one-liner any more: a line that pipes a download into a shell
# cannot be checked by anybody.
#
#   install.sh --sums-sha256 HASH --panel 100.x.y.z --join-stdin [--pair-v2]
#              [--power-control] [--self-update] [--wol] [--ups] [--ups-name NAME] [--ipmi] [--proxmox]
#
# The join code: --join-stdin reads it from the first line of standard input (what the panel's command does:
# printf '%s' CODE | sudo ... sh install.sh --join-stdin ...), or it is taken from the environment variable
# FAIRY_JOIN_CODE. Neither shows in the process list. --join CODE (older panels) still works; that form is
# readable by other local users while the script runs. The code is never printed and is handed to
# `fairy-agent join` on its standard input.
#
# --pair-v2 (the panel's command says so when the panel speaks it): the agent answers the panel encrypted, and
# only a panel that proves it has this join code.
#
# --sums-sha256 HASH (or FAIRY_SUMS_SHA256 in the environment): the SHA-256 of the release's SHA256SUMS, as the
# panel verified it with its own built-in release key. The script refuses a SHA256SUMS with any other hash
# before it trusts a line of it. Without it the script does not run, unless --unverified is given: then a
# first install rests on the downloaded program checking its own download, and the script says "NOT
# independently verified".
#
# It downloads the release (binary, SHA256SUMS + signature, the systemd units and rules), checks every file
# against SHA256SUMS and the signature with fairy-agent's built-in release key, then installs exactly what
# AGENT.md describes: user fairy-agent, /usr/local/bin/fairy-agent, /etc/fairy-agent (config.yaml and tokens
# 0640 root:fairy-agent), fairy-agent.service (+ fairy-agent-update.service when needed, one polkit rule per
# feature that is on: shutdown / reboot, self-update; the RAPL tmpfiles rule when the machine has RAPL), a
# firewall rule for the panel when ufw / firewalld is on.
# `fairy-agent join` then writes the tokens and the chosen settings (no editor, nothing to copy) and stores the
# one-time join code; the panel picks the tokens up by itself within a few seconds. With --proxmox (a standalone
# Proxmox VE node), join also makes the panel a read-only API token (user fairy@pve, role PVEAuditor, token
# fairy@pve!panel-<node>) that the panel picks up once with the agent's tokens; nothing to copy.
#
# Never older: when the installed fairy-agent is a newer build than this installer's release (a panel that
# pins an older release), the program and its unit files are kept and only settings and pairing are done.
#
# Safe to run again (with a new code from the panel's "Re-pair"): settings are kept, the tokens are replaced
# by new ones (the panel gets them by pairing), the binary and units are brought up to date. Nothing secret is
# printed.
set -eu

REPO="${FAIRY_REPO:-n3ptune-cpu/Fairy-agent}"
BASE="${FAIRY_RELEASE_URL:-https://github.com/$REPO/releases/latest/download}"
BIN=/usr/local/bin/fairy-agent
ETC=/etc/fairy-agent
UNITS=/etc/systemd/system
RULES=/etc/polkit-1/rules.d

# For every fairy-agent this script runs: this installer never replaces a newer program with an older release
# (step 3). A fairy-agent that guards itself against installers which do can tell the two apart by this.
FAIRY_INSTALLER_KEEPS_NEWER=1
export FAIRY_INSTALLER_KEEPS_NEWER

say() { printf '%s\n' "fairy: $*"; }
die() { printf '%s\n' "fairy: ERROR: $*" >&2; exit 1; }

CODE="" PANEL="" UPSNAME=""
CODE_ARG=0 CODE_STDIN=0 PAIRV2=0 UNVERIFIED=0
SUMS_PIN="${FAIRY_SUMS_SHA256:-}"
POWER=0 UPDATE=0 WOL=0 UPS=0 IPMI=0 PVE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --join) [ $# -ge 2 ] || die "--join needs the code"; CODE="$2"; CODE_ARG=1; shift ;;
    --join-stdin) CODE_STDIN=1 ;;
    --pair-v2) PAIRV2=1 ;;
    --panel) [ $# -ge 2 ] || die "--panel needs the panel's Tailscale address"; PANEL="$2"; shift ;;
    --power-control) POWER=1 ;;
    --self-update) UPDATE=1 ;;
    --wol) WOL=1 ;;
    --ups) UPS=1 ;;
    --ups-name) [ $# -ge 2 ] || die "--ups-name needs a name"; UPS=1; UPSNAME="$2"; shift ;;
    --ups=*) UPS=1; UPSNAME="${1#--ups=}" ;;
    --ipmi) IPMI=1 ;;
    --proxmox) PVE=1 ;;
    --sums-sha256) [ $# -ge 2 ] || die "--sums-sha256 needs the SHA-256 of SHA256SUMS"; SUMS_PIN="$2"; shift ;;
    --unverified) UNVERIFIED=1 ;;
    -h|--help) sed -n '2,43p' "$0" 2>/dev/null || true; exit 0 ;;
    *) die "unknown option (copy the whole command from the panel's Add host dialog)" ;;
  esac
  shift
done

# The join code: standard input, the environment, or (older panels, deprecated) the command line. It is never
# printed and never written anywhere by this script: no message shows an argument, nothing is traced, and
# fairy-agent join gets it on standard input.
if [ "$CODE_STDIN" -eq 1 ]; then
  [ "$CODE_ARG" -eq 0 ] || die "--join and --join-stdin cannot be used together"
  if [ -t 0 ]; then printf '%s' "fairy: paste the join code from the panel and press Enter: " >&2; fi
  IFS= read -r CODE || [ -n "$CODE" ] || die "--join-stdin: no join code on standard input"
elif [ "$CODE_ARG" -eq 0 ]; then
  CODE="${FAIRY_JOIN_CODE:-}"
fi
unset FAIRY_JOIN_CODE # not for the programs this script starts
if [ "$CODE_ARG" -eq 1 ]; then
  # one line, on standard error, and never the code itself
  printf '%s\n' "fairy: warning: --join CODE on the command line is deprecated and will stop working in a later release: other users of this machine can read the code while this runs, and sudo's log and the shell history keep it. Use the command the panel shows now (--join-stdin)." >&2
fi
CODE="$(printf '%s' "$CODE" | tr -d '\r')"
[ -n "$CODE" ] && [ -n "$PANEL" ] ||
  die "usage: install.sh --sums-sha256 HASH --panel PANEL_TAILSCALE_IP --join-stdin [options] (use the command from the panel's Add host dialog)"
case "$CODE" in
  *[!A-Za-z2-7\ -]*) die "that is not a Fairy join code (letters A-Z and digits 2-7, in groups of four)" ;;
esac
case "$PANEL" in *[!0-9.]*) die "--panel must be the panel's Tailscale IPv4 address, e.g. 100.64.0.10" ;; esac
case "$UPSNAME" in *[!A-Za-z0-9_.-]*) die "--ups-name: letters, digits, _ . - only (the name in upsc -l)" ;; esac

# The release's fingerprint from the panel. Without it nothing vouches for a first download but itself.
if [ -n "$SUMS_PIN" ]; then
  SUMS_PIN="$(printf '%s' "$SUMS_PIN" | tr 'A-F' 'a-f')"
  case "$SUMS_PIN" in
    *[!0-9a-f]*) die "FAIRY_SUMS_SHA256 / --sums-sha256 must be 64 hex digits (the SHA-256 of SHA256SUMS)" ;;
  esac
  [ "${#SUMS_PIN}" -eq 64 ] || die "FAIRY_SUMS_SHA256 / --sums-sha256 must be 64 hex digits (the SHA-256 of SHA256SUMS)"
elif [ "$UNVERIFIED" -eq 0 ]; then
  die "no release fingerprint (--sums-sha256). Use the command from the panel's Add host dialog: it carries the fingerprint of the release the panel checked. To install without it, at your own risk, add --unverified"
fi
[ "$(id -u)" -eq 0 ] || die "run it as root (the panel's command uses sudo)"
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

say "downloading the release from $BASE"
POLKIT_POWER=fairy-agent-power.polkit.rules
POLKIT_UPDATE=fairy-agent-update.polkit.rules
FILES="$ASSET SHA256SUMS SHA256SUMS.sig VERSION fairy-agent.service fairy-agent-update.service $POLKIT_POWER $POLKIT_UPDATE fairy-agent.tmpfiles.conf"
for f in $FILES; do
  curl -fsSL --proto '=https,file' --proto-redir '=https' --retry 3 -o "$TMP/$f" "$BASE/$f" || die "download of $f failed"
done

# 0. SHA256SUMS itself must be the one the panel vouched for (when it passed its hash)
if [ -n "$SUMS_PIN" ]; then
  got="$(sha256sum "$TMP/SHA256SUMS" | awk '{ print $1 }')"
  [ "$got" = "$SUMS_PIN" ] || die "SHA256SUMS is not the release the panel checked (SHA-256 $got, expected $SUMS_PIN)"
  say "SHA256SUMS matches the hash the panel checked"
fi

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
#    can (a re-run), else the new one's
rc=2
by=""
if [ -x "$BIN" ]; then
  "$BIN" verify-release "$TMP" >/dev/null 2>&1 && rc=0 || rc=$?
  [ "$rc" -eq 1 ] && die "the release signature does not match the installed fairy-agent's release key"
  by="the installed fairy-agent's release key"
fi
if [ "$rc" -ne 0 ]; then
  "$TMP/$ASSET" verify-release "$TMP" >/dev/null 2>&1 && rc=0 || rc=$?
  by="the downloaded fairy-agent's own release key"
fi
NEWVER="$(awk 'NR == 1 { print $2 }' "$TMP/VERSION")"
case "$rc" in
  0) if [ -n "$SUMS_PIN" ]; then
       say "release $NEWVER verified (the panel's fingerprint, SHA256SUMS signature and hashes)"
     elif [ "$by" = "the installed fairy-agent's release key" ]; then
       say "release $NEWVER verified with $by (no fingerprint from the panel: --unverified)"
     else
       say "WARNING: release $NEWVER is NOT independently verified: no fingerprint from the panel (--unverified), and"
       say "WARNING: its signature was checked only with $by, which came with the same download"
     fi ;;
  3) [ -n "$SUMS_PIN" ] || die "this build has no release key and no fingerprint from the panel was given: nothing vouches for it"
     say "WARNING: this build has no release key, the signature was not checked (the panel's fingerprint and hashes only)" ;;
  *) die "the release signature check failed" ;;
esac

# 3. never older: an installed fairy-agent that is a newer build than this release stays
build_of() { # the build number at the start of a version ("42-1a2b3c4" -> 42); nothing for other formats
  b="${1%%-*}"
  case "$b" in ''|*[!0-9]*) return 0 ;; esac
  [ "${#b}" -le 9 ] || return 0
  b="$(printf '%s' "$b" | sed 's/^0*//')"
  printf '%s' "${b:-0}"
}
KEEP=0
HAVE=""
if [ -x "$BIN" ]; then
  HAVE="$("$BIN" version 2>/dev/null | awk 'NR == 1 && $1 == "fairy-agent" { print $2 }')" || HAVE=""
fi
have_n="$(build_of "$HAVE")"
new_n="$(build_of "$NEWVER")"
if [ -n "$have_n" ]; then
  [ -n "$new_n" ] ||
    die "this release's version ($NEWVER) has no build number, so it cannot be told whether it is older than the installed fairy-agent $HAVE: not installed (by hand, to force it: fairy-agent update --force)"
  if [ "$have_n" -gt "$new_n" ]; then KEEP=1; fi
fi
if [ "$KEEP" -eq 1 ]; then
  say "the installed fairy-agent $HAVE is NEWER than this installer's release $NEWVER:"
  say "  the program and its unit files are kept as they are; only the settings and the pairing are done."
  say "  (The panel that made this command pins an older agent release: update the panel.)"
fi

# 4. user, program, folders (AGENT.md, "Install on Linux")
if ! id fairy-agent >/dev/null 2>&1; then
  nologin="$(command -v nologin 2>/dev/null || echo /usr/sbin/nologin)"
  useradd --system --no-create-home --shell "$nologin" fairy-agent
  say "created the system user fairy-agent"
fi
if [ "$KEEP" -eq 0 ]; then
  install -m 0755 "$TMP/$ASSET" "$BIN.new"
  mv -f "$BIN.new" "$BIN"
  command -v restorecon >/dev/null 2>&1 && restorecon "$BIN" || true
fi
install -d -m 0750 -o root -g fairy-agent "$ETC"
install -d -m 0700 -o fairy-agent -g fairy-agent /var/lib/fairy-agent

# 5. units (an existing unit that differs is kept as .bak; with a newer agent installed, existing units stay)
put() { # put SRC DEST MODE
  if [ -f "$2" ] && ! cmp -s "$1" "$2"; then
    if [ "$KEEP" -eq 1 ]; then return 0; fi
    cp -p "$2" "$2.bak"
    say "kept your previous $2 as $2.bak"
  fi
  install -m "$3" "$1" "$2"
}
put "$TMP/fairy-agent.service" "$UNITS/fairy-agent.service" 0644
if [ "$UPDATE" -eq 1 ] || [ -f "$UNITS/fairy-agent-update.service" ]; then
  put "$TMP/fairy-agent-update.service" "$UNITS/fairy-agent-update.service" 0644
fi
if ls /sys/class/powercap/intel-rapl:*/energy_uj >/dev/null 2>&1; then
  put "$TMP/fairy-agent.tmpfiles.conf" /etc/tmpfiles.d/fairy-agent.conf 0644
  systemd-tmpfiles --create /etc/tmpfiles.d/fairy-agent.conf || true
fi

# 6. firewall: only the panel, only on the Tailscale interface
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "^Status: active"; then
  ufw allow in on tailscale0 from "$PANEL" to any port 9101 proto tcp >/dev/null && say "ufw: allowed $PANEL to port 9101 on tailscale0"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  rule="rule family=ipv4 source address=$PANEL/32 port port=9101 protocol=tcp accept"
  firewall-cmd -q --permanent --add-rich-rule="$rule" && firewall-cmd -q --reload && say "firewalld: allowed $PANEL to port 9101"
fi

# 7. tokens, settings and the join code. The code goes to fairy-agent join on its standard input, never on a
#    command line (which every local user can read while a program runs); join prints no secret.
set -- --code-stdin --panel "$PANEL"
[ "$PAIRV2" -eq 1 ] && set -- "$@" --pair-v2
[ "$POWER" -eq 1 ] && set -- "$@" --power-control
[ "$UPDATE" -eq 1 ] && set -- "$@" --self-update
[ "$WOL" -eq 1 ] && set -- "$@" --wol
[ "$IPMI" -eq 1 ] && set -- "$@" --ipmi
[ "$PVE" -eq 1 ] && set -- "$@" --proxmox
if [ "$UPS" -eq 1 ]; then
  if [ -n "$UPSNAME" ]; then set -- "$@" --ups-name "$UPSNAME"; else set -- "$@" --ups; fi
fi
"$BIN" join "$@" <<EOF
$CODE
EOF
CODE=""

# 8. polkit: one rule file per feature, only for a feature that is on in config.yaml now (join only ever
#    switches features on, so this is asked of the config, not of this run's options). A rule whose feature is
#    off is removed, and so is the combined file of older installers, which granted both rights for either.
feature_on() { # feature_on KEY FALLBACK: is KEY true in config.yaml (FALLBACK when the config cannot be asked)
  v="$("$BIN" config get "$1" 2>/dev/null)" || v=""
  case "$v" in
    true) return 0 ;;
    false) return 1 ;;
  esac
  [ "$2" -eq 1 ]
}
want_power=0
want_update=0
if feature_on power_control.enabled "$POWER"; then want_power=1; fi
if feature_on self_update.enabled "$UPDATE"; then want_update=1; fi
if [ "$want_power" -eq 1 ] || [ "$want_update" -eq 1 ]; then
  if [ ! -d "$RULES" ]; then
    if command -v apt-get >/dev/null 2>&1; then
      say "installing polkitd (needed for shutdown / reboot and self-update)"
      DEBIAN_FRONTEND=noninteractive apt-get install -y -q polkitd >/dev/null || apt-get install -y -q policykit-1 >/dev/null
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y -q polkit >/dev/null
    fi
  fi
  [ -d "$RULES" ] || die "polkit is not installed (needed for shutdown / reboot and self-update)"
fi
polkit_rule() { # polkit_rule WANTED SRC DEST WHAT
  if [ "$1" -eq 1 ]; then
    if [ ! -f "$3" ] || ! cmp -s "$2" "$3"; then
      install -m 0644 "$2" "$3"
      say "polkit: the agent's user may $4 ($3)"
    fi
  elif [ -e "$3" ]; then
    rm -f "$3"
    say "polkit: removed $3 (the agent's user may no longer $4: that feature is off)"
  fi
}
if [ -d "$RULES" ]; then
  polkit_rule "$want_power" "$TMP/$POLKIT_POWER" "$RULES/49-fairy-agent-power.rules" "power off, reboot and suspend this machine"
  polkit_rule "$want_update" "$TMP/$POLKIT_UPDATE" "$RULES/49-fairy-agent-update.rules" "start the self-update installer"
  if [ -e "$RULES/49-fairy-agent.rules" ]; then
    rm -f "$RULES/49-fairy-agent.rules"
    say "polkit: removed the old combined rule $RULES/49-fairy-agent.rules (now one file per feature)"
  fi
fi

systemctl daemon-reload
systemctl enable -q fairy-agent
systemctl restart fairy-agent
if [ "$KEEP" -eq 1 ]; then RUNNING="$HAVE"; else RUNNING="$NEWVER"; fi
say "fairy-agent $RUNNING started; waiting for the panel to pair (keep the Add host dialog open) ..."

# 9. wait (up to 2 minutes) until the panel has picked up the tokens
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
