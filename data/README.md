# Offline MAC vendor assignments

`vendors.tsv` is generated from the public IEEE Registration Authority listings:
https://standards.ieee.org/products-programs/regauth/

It contains the MA-L (24-bit), MA-M (28-bit), MA-S (36-bit), and legacy IAB
(36-bit) assignments. The file header records retrieval date, source URLs, and
SHA-256 checksums of the downloaded CSV files. Organization names and assignments
come from IEEE's public registries; names identify the registered address-block
holder, which may be the network adapter manufacturer rather than device brand.

Refresh and rebuild:

```sh
python3 scripts/update-vendors.py
cargo build --release --locked
```

The application embeds the snapshot at build time; lookups require no network
connection and never send device MAC addresses to a service. The most specific
matching assignment wins. Private/local MACs cannot reliably identify a vendor,
and assignments missing from the snapshot are reported as such.
