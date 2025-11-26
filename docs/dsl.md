# RuleGenie Generic Detection DSL

The DSL is a lightweight, Sigma-inspired structure for expressing detection logic that can be exported to Sigma YAML or vendor-like queries.

## Schema
```yaml
title: <string>                # required
description: <string>
logsource:
  platform: <windows/linux/o365/...>
  product: <sysmon/security/...>
  service: <service/category name>
  category: <category>
detection:
  selections:                  # required, one or more named selections
    sel1:
      Field|operator: value
      OtherField: exact_value  # operator defaults to equals
  condition: "sel1 and not sel2"   # boolean expression over selection names
  timeframe: "5m"              # optional; not enforced in v0.1
  aggregation:                 # optional; simplified count thresholds
    op: count|distinct_count
    field: <field name or null>
    threshold: <int>
    window: "5m"
fields: [list, of, returned, fields]
tags: [labels]
severity: low|medium|high|critical
mitre: [Txxxx.xxx]
```

## Supported operators
- `equals` (default when no operator suffix)
- `contains`
- `startswith`
- `endswith`
- `in`, `not_in` (value must be a list/array)
- `gt`, `gte`, `lt`, `lte`

Example selection:
```yaml
selections:
  sel1:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-enc'
  exclude_admin:
    User|equals: 'Administrator'
condition: "sel1 and not exclude_admin"
```

## Mapping to Sigma
- `logsource` maps directly to Sigma `logsource`.
- Each selection becomes a Sigma selection block; operators are rendered using the Sigma `field|operator` syntax.
- `condition` is copied as-is when it only contains selection names and boolean operators.
- `severity` → Sigma `level`
- `mitre` → Sigma `references` (for v0.1)

## Export functions
- `generic_rule_to_sigma(rule: GenericRule) -> str` produces a Sigma YAML string for the supported subset.
- `generic_rule_to_pseudo_query(rule: GenericRule) -> str` produces a readable boolean query string for CLIs or placeholder vendor queries.

## Validation rules
- At least one selection required.
- Operators must be in the supported list.
- `condition` may reference only defined selections and boolean operators (`and`, `or`, `not`).
- Aggregation requires `threshold` and `window`; not enforced at runtime in v0.1.
