# summary

Initialises classifications and policies for a security audit.

# description

Exports permissions (standard and custom), permission sets, profiles, users, etc from the target org. All classifications are initialised with sane defaults that you can customize later.

# flags.target-org.summary

Target org to export permissions, profiles, users, etc.

# flags.output-dir.summary

Directory where the audit config is initialised. If not set, the root directory will be used.

# flags.preset.summary

Select a preset to initialise classifications.

# flags.preset.description

Preset is processed last (after custom templates) and initialises defaults for user permission classifications and the enabled rules for each policy. Consult the documentation to learn more.

# examples

- Initialise audit policies at the root directory

  <%= config.bin %> <%= command.id %> -o MyTargetOrg

# success.perm-classification-summary

Initialised %s permissions at %s.

# success.policy-summary

Initialised "%s" policy with %s rule(s) at %s.
