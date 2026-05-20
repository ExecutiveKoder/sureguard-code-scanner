# Sureguard rule packs

These are the **AI-aware** patterns. They focus on the failure modes LLM-generated code actually exhibits — disabled TLS, MD5, `eval`, hardcoded secrets, SQL string concat, JWT `alg=none` — not the firehose of generic SAST findings.

## Layout

```
rules/
├── python/        # rule packs targeting Python
├── javascript/    # JS and TS (Semgrep handles both with one ruleset)
└── README.md
```

Each `.yml` file is a Semgrep ruleset. Categories:

- `insecure-crypto.yml` — weak hashes, weak PRNGs, broken cipher modes
- `disabled-tls.yml` — anything that turns off cert verification
- `injection.yml` — SQL string concat, shell interpolation, eval/exec
- `jwt.yml` — alg=none, signature-skipping, wildcard CORS

## Contributing a rule

1. Use a stable `id` of the form `sureguard.<language>.<concept>`. This ID surfaces in SARIF and findings; don't rename casually.
2. Set `severity` honestly: `ERROR` only if it's exploitable as written. `WARNING` for "almost always wrong but plausibly intentional."
3. Add `metadata.category`, `metadata.cwe`, and `metadata.fix` — the fix string is what the AI reviewer hands the developer.
4. Test against a known-bad and a known-good snippet (`tests/rule_fixtures/`).

## Out of scope

We don't ship rules for things upstream tools already do well: generic taint analysis, framework-specific best practices, style. The whole point of this pack is the narrow LLM-specific layer.
