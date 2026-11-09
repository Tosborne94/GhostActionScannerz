#!/usr/bin/env bash
# GhostAction GitHub-side scan: injected workflows + their runs, commit/code search.
# Env: OWNER (user/org), GH_TOKEN (repo + actions:read; code search needs a token), REPOS (optional "o/r o/r").
api() { curl -fsSL ${GH_TOKEN:+-H "Authorization: Bearer $GH_TOKEN"} -H 'Accept: application/vnd.github+json' "https://api.github.com/$1" || { echo "::error::API call failed: $1" >&2; : >"$ERR"; }; }
ERR=$(mktemp -u)  # fail closed: any API error means "unknown", never "clean"
WF='security-audit\.yml|github_actions_security\.yml'
if [ -z "${REPOS:-}" ]; then
  [ "$(api "users/$OWNER" | jq -r .type)" = Organization ] && L="orgs/$OWNER/repos?type=all" || L="users/$OWNER/repos?type=owner"
  [ -n "${GH_TOKEN:-}" ] && [ "$(api user | jq -r .login)" = "$OWNER" ] && L="user/repos?affiliation=owner"
  REPOS=$(p=1; while r=$(api "$L&per_page=100&page=$p" | jq -r '.[].full_name') && [ -n "$r" ]; do echo "$r"; p=$((p+1)); done)
fi
out=$(for r in $REPOS; do
  # runs outlive the deleted workflow file (the workflows API forgets it), so query runs directly
  # shortcut: only runs since 2026-09-01 and first 100 per repo; widen if the campaign is older/busier
  api "repos/$r/actions/runs?per_page=100&created=%3E%3D2026-09-01" | jq -r --arg wf "$WF" --arg r "$r" '.workflow_runs[]|select(.path|test($wf))|"\($r): RUN of \(.path) (success = secrets exfiltrated): \(.created_at) \(.conclusion) by \(.actor.login) \(.html_url)"'
done
for m in 'Add security audit workflow' 'Update security audit workflow' 'Add Github Actions Security workflow'; do
  api "search/commits?q=$(jq -rn --arg q "\"$m\" user:$OWNER" '$q|@uri')" | jq -r '.items[]|"\(.repository.full_name): malicious commit: \(.sha[0:8]) \(.commit.author.date) \(.commit.message|split("\n")[0])"'
done
[ -n "${GH_TOKEN:-}" ] && api "search/code?q=$(jq -rn --arg q "193.32.204.199 user:$OWNER" '$q|@uri')" | jq -r '.items[]|"\(.repository.full_name): C2 IP in default branch: \(.path)"')
[ -n "$out" ] && { echo "$out"; echo "::error::GhostAction IoCs found - see https://socket.dev/blog/ghostaction-cloud-credentials#Recommended-Actions"; exit 1; }
[ -e "$ERR" ] && { echo "::error::Scan incomplete (API errors above; check token/rate limit)"; exit 2; }
echo "No GhostAction IoCs found on GitHub for $OWNER."
