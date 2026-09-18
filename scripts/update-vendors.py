#!/usr/bin/env python3
"""Refresh the bundled offline vendor database from IEEE's public registries."""

import csv
import datetime
import hashlib
import io
from pathlib import Path
import urllib.request


def main():
    registries = [("oui/oui.csv", 6), ("oui28/mam.csv", 7),
                  ("oui36/oui36.csv", 9), ("iab/iab.csv", 9)]
    assignments = {}
    sources = []
    for registry, digits in registries:
        url = "https://standards-oui.ieee.org/" + registry
        request = urllib.request.Request(url, headers={"User-Agent": "NetworkScanner-VendorUpdater/1.0"})
        with urllib.request.urlopen(request, timeout=60) as response:
            content = response.read(20_000_001)
        if len(content) > 20_000_000:
            raise ValueError("Registry exceeds size limit: " + url)
        records = list(csv.DictReader(io.StringIO(content.decode("utf-8-sig"))))
        if len(records) < 1000:
            raise ValueError("Unexpectedly small registry: " + url)
        for record in records:
            prefix = record["Assignment"].strip().upper()
            vendor = " ".join(record["Organization Name"].split())
            if len(prefix) != digits or not vendor or any(c not in "0123456789ABCDEF" for c in prefix):
                raise ValueError("Invalid registry entry: " + repr(record))
            assignments[prefix] = vendor
        sources.append(f"# {url} SHA256={hashlib.sha256(content).hexdigest()}")
        print(f"{registry}: {len(records):,} entries", flush=True)
    output = Path(__file__).resolve().parent.parent / "data" / "vendors.tsv"
    output.parent.mkdir(parents=True, exist_ok=True)
    header = ["# IEEE public MAC address assignments (MA-L, MA-M, MA-S, IAB)",
              "# Retrieved " + datetime.datetime.now(datetime.timezone.utc).date().isoformat(),
              *sources, "# Hex prefix (24/28/36 bits)\\tOrganization name"]
    text = "\n".join(header + [f"{prefix}\t{vendor}" for prefix, vendor in sorted(assignments.items())]) + "\n"
    temporary = output.with_suffix(".tsv.tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(output)
    print(f"Saved {len(assignments):,} assignments to {output}")


if __name__ == "__main__":
    main()
