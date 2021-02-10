# Semgrep Bandit ruleset

[bandit.yml](rules/bandit.yml) is a semgrep rule-set that covers all the rules
that are implemented in [bandit v1.7.0](https://github.com/PyCQA/bandit).

Every semgrep rule contains the bandit identifier (`BXXX`) for the rule it
covers in its in its name (`id` property).

For cases where multiple semgrep rules are covering a single bandit pattern, we
suffix the semgrep rule `id` with a sequence number , e.g., `BXXX-1` and
`BXXX-N`. 

For cases where a single semgrep rule covers multiple bandit patterns at once,
we use `BXXX.BYYY...` as rule `id` (bandit pattern `ids` separated by `.`)
where `BXXX` and `BYYY` are both covered by a single semgrep rule.

For rules that originate from sources such as [semgrep bandit ruleset](https://semgrep.dev/c/p/bandit) 
or the [semgrep rules repository](https://github.com/returntocorp/semgrep-rules), we added an
inline comment `# source (<modtype>): https://<source>` that documents the source 
where `<modtype>` can be a combination of `combined`, `modified` or `original` 
separated by `/`:
- `combined`: rule is a combination of multiple source rules
- `modified`: rule is a modified version of the original rule
- `original`: rule is an exact copy of the original rule 

We also provide the original rule `id` (from the source rule) in an inline
comment right above the `id` property. The original `id` uniquely identifies a
rule within the [semgrep rules repository](https://github.com/returntocorp/semgrep-rules).
Hence, it is useful for tracking changes and/or upstream contributions.
