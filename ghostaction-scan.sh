#!/usr/bin/env bash
# GhostAction IoC scanner (https://socket.dev/blog/ghostaction-cloud-credentials)
# Usage: ghostaction-scan.sh [--secrets] [dir ...]   Exit 1 if IoCs found.
S=0; [ "${1:-}" = --secrets ] && { S=1; shift; }
IP='193\.32\.204\.199'; WF='.github/workflows/security-audit.yml .github/workflows/github_actions_security.yml'
MSG='^(Add security audit workflow|Update security audit workflow|Add Github Actions Security workflow)$'
SEC='AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|aws_secret_access_key|aws_session_token|sk-(ant|proj|or)-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|glpat-[A-Za-z0-9_-]{20}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[A-Za-z0-9-]{10,}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'
ERR=$(mktemp -u); SEEN=$(mktemp -u)  # fail closed: any git/find error means "unknown", never "clean"
G() { git -C "$r" "$@" || { echo "ERROR: git $1 failed in $r" >&2; : >"$ERR"; }; }
out=$({ find "${@:-.}" -name .git -prune || : >"$ERR"; } | while read -r g; do r=${g%/.git}; : >"$SEEN"
  for f in $WF; do [ -f "$r/$f" ] && echo "$r: workflow present: $f"; done
  grep -rlE "$IP|AKIA_CTX_(START|END)|c=monami" "$r/.github/workflows" 2>/dev/null | sed 's/^/C2 marker in workflow: /'
  G log --all -E --grep="$MSG" --format="$r: malicious commit: %h %an %ad %s"
  G log --all --diff-filter=A --format="$r: workflow added: %h %an %ad" -- $WF
  G log --all -G"$IP" --format="$r: C2 IP in commit: %h %an %ad %s"
  [ $S = 1 ] && G log --all -p --format='commit %h' | grep -oE "^commit .*|$SEC" | awk -v r="$r" '/^commit /{c=$2;next}{print r": credential in history (rotate): "c" "substr($0,1,8)"…"}'
done)
[ -n "$out" ] && { echo "$out"; echo "IoCs FOUND - see #Recommended-Actions in the Socket post"; exit 1; }
[ -e "$ERR" ] && { echo "Scan INCOMPLETE (errors above)"; exit 2; }
[ -e "$SEEN" ] || { echo "No git repos found under: ${*:-.}"; exit 2; }
echo "No GhostAction IoCs found."
