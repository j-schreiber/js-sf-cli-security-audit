# summary

Initialises classifications and policies for a security audit.

# description

Exports permissions (standard and custom), permission sets, profiles, users, etc from the target org. All classifications are initialised with sane defaults that you can customize later.

# flags.target-org.summary

Target org to export permissions, profiles, users, etc.

# flags.output-dir.summary

Directory where the audit config is initialised. If not set, the root directory will be used.

# flags.preset.summary

Select a preset to initialise permission classifications (risk levels).

# flags.preset.description

The selected preset is applied before any other default mechanisms (such as template configs). This means, values from a selected template override the preset. Consult the documentation to learn more about the rationale behind the default risk levels. The risk levels interact with the configured preset on profiles and permission sets and essentially control, if a permission is allowed in a certain profile / permission set.

# examples

- Initialise audit policies at the root directory

  <%= config.bin %> <%= command.id %> -o MyTargetOrg

- Initialise audit config at custom directory with preset

  <%= config.bin %> <%= command.id %> -o MyTargetOrg -d my_dir -p loose

# success.perm-classification-summary

Initialised %s permissions at %s.

# success.policy-summary

Initialised "%s" policy with %s rule(s) at %s.
