# Keylimectl, a Go rewrite of (keylime-)tenant.py

Warning: under development

Keylimectl is a tool to query and act on a
[Keylime](https://github.com/keylime/keylime) cluster.

This README will be fleshed out as the tool is built.

## Of note
Currently, keylime.conf does not have a configuration element for the API
version.
Keylimectl defines it using a flag (--api-version) which defaults to v1.
