# Harp Audit

This tool is a Harp bundle processor used to audit a bundle content.

## Usage 

```sh
$ harp from <source> --out secret.bundle
$ harp bundle filter --in secret.bundle <additional parameters> | harp-audit | jq
```
