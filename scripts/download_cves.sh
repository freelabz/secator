#!/bin/bash

wget https://cve.circl.lu/static/circl-cve-search-expanded.json.gz
gunzip circl-cve-search-expanded.json.gz
mkdir -p /tmp/cves

while IFS= read -r line
do
    cve_id=$(jq -r '.id' <<< $line)
    echo $line > /tmp/cves/$cve_id.json
    echo "CVE saved to /tmp/cves/$cve_id.json"
done < "circl-cve-search-expanded.json"

rm circl-cve-search-expanded.json.gz || true
rm circl-cve-search-expanded.json || true