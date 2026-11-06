#!/usr/bin/env bash
# Read-only probes of the public cheqd resolver for a real testnet status list resource.
# Taken from Studio's e2e fixtures (a StatusList2021Revocation resource created in 2023).
set -u
D=did:cheqd:testnet:0c3581f0-011f-4263-b1ca-15ad70d54ede
ID=1a79a313-8fc3-421c-af3d-34730fa046d1
N=cheqd-employee-credentials-unencrypted
T=StatusList2021Revocation
R=https://resolver.cheqd.net/1.0/identifiers

echo "== data by name + type (latest)"
curl -s -o /tmp/sl.body "$R/$D?resourceName=$N&resourceType=$T"; head -c 300 /tmp/sl.body; echo
echo "== metadata (checksum, version, previous/next ids)"
curl -s "$R/$D?resourceName=$N&resourceType=$T&resourceMetadata=true" | python3 -c "import sys,json;print(json.dumps(json.load(sys.stdin)['contentMetadata']['linkedResourceMetadata'],indent=1))"
echo "== sha256 of the returned bytes"
shasum -a 256 /tmp/sl.body | cut -d' ' -f1
echo "== direct by resource id (same bytes?)"
curl -s -o /tmp/sl2.body "$R/$D/resources/$ID"; cmp /tmp/sl.body /tmp/sl2.body && echo same
echo "== version time before creation (expect 404)"
curl -s -o /dev/null -w "HTTP %{http_code}\n" "$R/$D?resourceName=$N&resourceType=$T&resourceVersionTime=2023-01-01T00:00:00Z"
echo "== node REST for the resource module (second source; expect 501 on api.cheqd.network)"
curl -s -m 10 -w " [HTTP %{http_code}]\n" "https://api.cheqd.network/cheqd/resource/v2/collection/0c3581f0-011f-4263-b1ca-15ad70d54ede/resources/$ID/metadata"
