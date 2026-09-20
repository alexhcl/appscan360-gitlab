#!/usr/bin/env bash
# Stamp your own GitHub (or GitLab) repo into every template and the pipeline config.
#   ./set-origin.sh alex-m1/appscan360-gitlab [main]
#   ./set-origin.sh https://gitlab.example.com/sec/appscan360-gitlab [main]   (GitLab: raw URL becomes /-/raw/)
set -e
repo="${1:?usage: set-origin.sh <owner/repo | full url> [ref]}"; ref="${2:-main}"
if [[ "$repo" == http* ]]; then
  clone="${repo%.git}.git"; raw="${repo%.git}/-/raw/$ref"
else
  clone="https://github.com/$repo.git"; raw="https://raw.githubusercontent.com/$repo/$ref"
fi
files=(yaml/*.yaml README.md examples/*.yaml examples/*.yml)
sed -i -E "s#https://raw\.githubusercontent\.com/alex-m1/appscan360-gitlab/[^/]+#$raw#g; s#https://github\.com/alex-m1/appscan360-gitlab\.git#$clone#g; s#(APPSCAN_SCRIPTS_GIT_REF: \")[^\"]*#\1$ref#g" "${files[@]}"
echo "Templates now point to: $raw  (clone $clone, ref $ref)"
