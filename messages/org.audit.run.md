# summary

Audit your org.

# description

Loads a given audit config (a set of classifications and policies) and runs the policies against the target org. The audit run creates a comprehensive report that lists all executed policies and all resolved entities that were audited.

# flags.target-org.summary

The org that is audited.

# flags.source-dir.summary

Location of the audit config.

# flags.source-dir.description

Loads all classifications and policies from the directory and uses them to audit the org. Only policies that are enabled and that exist in the directory are executed.

# examples

- Audit the org MyTargetOrg with the config in configs/prod

  <%= config.bin %> <%= command.id %> -o MyTargetOrg -d configs/prod

# success.summary

Successfully executed %s policies.

# success.all-policies-compliant

All policies are compliant.

# summary-non-compliant

At least one policy is not compliant. Review details below.

# info.report-file-location

Full report was written to: %s.
