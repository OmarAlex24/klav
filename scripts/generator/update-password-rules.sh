#!/bin/sh
# Updates the site data that klav-core bundles from
# apple/password-manager-resources (ADR 0022 §1.3): the password rules and
# the change-password pages.
#
#   scripts/generator/update-password-rules.sh <commit SHA>
#
# Downloads `quirks/password-rules.json`, `quirks/change-password-URLs.json`
# and `LICENSE.md` at that exact commit, checks that the licence is still
# the MIT text, and rewrites `crates/klav-core/src/generator/password-rules.json`,
# `change-password-urls.json` and their notices. Klav never fetches these
# files at run time: this script is the only way they change, and the
# result is reviewed in a pull request.
#
# After running it: `cargo test -p klav-core generator` (every bundled
# rule must parse, every change page must be an https URL) and commit the
# four files.
set -eu

ref=${1:?usage: update-password-rules.sh <commit SHA of apple/password-manager-resources>}
case $ref in
*[!0-9a-f]* | "") echo "expected a full commit SHA (40 hex characters)" >&2 && exit 2 ;;
esac
[ ${#ref} -eq 40 ] || { echo "expected a full commit SHA (40 hex characters)" >&2 && exit 2; }

root=$(cd "$(dirname "$0")/../.." && pwd)
dest="$root/crates/klav-core/src/generator"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

base="https://raw.githubusercontent.com/apple/password-manager-resources/$ref"
curl -sfL "$base/quirks/password-rules.json" -o "$work/password-rules.json"
curl -sfL "$base/quirks/change-password-URLs.json" -o "$work/change-password-urls.json"
curl -sfL "$base/LICENSE.md" -o "$work/LICENSE.md"

# The MIT grant and its notice condition, word for word.
grep -q "Permission is hereby granted, free of charge, to any person obtaining a copy" "$work/LICENSE.md"
grep -q "The above copyright notice and this permission notice shall be included" "$work/LICENSE.md"
copyright=$(grep -m1 "^Copyright" "$work/LICENSE.md")

# Every entry must be {"password-rules": "…"}; anything else means the
# format changed and klav-core's loader has to be reviewed first.
python3 -I - "$work/password-rules.json" <<'EOF'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
assert isinstance(data, dict) and data, "expected a non-empty object"
for domain, entry in data.items():
    assert domain == domain.strip().lower() and "." in domain, domain
    assert isinstance(entry, dict) and set(entry) == {"password-rules"}, domain
    assert isinstance(entry["password-rules"], str), domain
print(f"{len(data)} domains")
EOF

# Every entry must be "domain": "https://…".
python3 -I - "$work/change-password-urls.json" <<'EOF'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
assert isinstance(data, dict) and data, "expected a non-empty object"
for domain, url in data.items():
    assert domain == domain.strip().lower() and "." in domain, domain
    assert isinstance(url, str) and url.startswith("https://"), domain
print(f"{len(data)} change-password pages")
EOF

cp "$work/password-rules.json" "$dest/password-rules.json"
sum=$(shasum -a 256 "$dest/password-rules.json" | cut -d' ' -f1)
today=$(date -u +%Y-%m-%d)
{
	echo "# Per-site password rules"
	echo
	echo "\`password-rules.json\` is \`quirks/password-rules.json\` from [apple/password-manager-resources](https://github.com/apple/password-manager-resources), unchanged, at commit [\`$ref\`](https://github.com/apple/password-manager-resources/tree/$ref) (SHA-256 \`$sum\`, downloaded on $today with \`scripts/generator/update-password-rules.sh\`)."
	echo
	echo "Each entry gives, for a domain, the site's password rules in the \`passwordrules\` grammar. The smart generator in \`klav-core\` reads them without network (ADR 0022 §1.3)."
	echo
	echo "MIT license:"
	echo
	sed 's/^/> /; s/^> $/>/' "$work/LICENSE.md"
} >"$dest/PASSWORD-RULES-NOTICE.md"

cp "$work/change-password-urls.json" "$dest/change-password-urls.json"
sum=$(shasum -a 256 "$dest/change-password-urls.json" | cut -d' ' -f1)
{
	echo "# Change-password pages per site"
	echo
	echo "\`change-password-urls.json\` is \`quirks/change-password-URLs.json\` from [apple/password-manager-resources](https://github.com/apple/password-manager-resources), unchanged, at commit [\`$ref\`](https://github.com/apple/password-manager-resources/tree/$ref) (SHA-256 \`$sum\`, downloaded on $today with \`scripts/generator/update-password-rules.sh\`)."
	echo
	echo "Each entry gives, for a domain, the page where the password is changed. Assisted password change offers it to the agent with \`change_password_url\`, without network; if the site isn't listed, Klav uses \`https://<host>/.well-known/change-password\`, with the item's port if its URL carries a different one (ADR 0022 §1.3 and §5)."
	echo
	echo "MIT license:"
	echo
	sed 's/^/> /; s/^> $/>/' "$work/LICENSE.md"
} >"$dest/CHANGE-PASSWORD-URLS-NOTICE.md"

echo "Updated $dest/password-rules.json and change-password-urls.json ($copyright)"
