# summary

Initialise a new audit config.

# description

Uses your org's configuration to set up a new audit config at the target destination. This creates the basic classification and policy files that make up an audit config. You can select from presets to initialise risk levels with default values. After initialisation, you can customize the files to suit your needs.

# flags.target-org.summary

Target org to export permissions, profiles, users, etc.

# flags.output-dir.summary

Directory where the audit config is initialised. If not set, the root directory will be used.

# flags.preset.summary

Preset to initialise defaults for permission risk levels.

# flags.preset.description

The selected preset is applied before any other default mechanisms (such as template configs). This means, values from a selected template override the preset. Consult the documentation to learn more about the rationale behind the default risk levels. The risk levels interact with the configured preset on profiles and permission sets and essentially control, if a permission is allowed in a certain profile / permission set.

# examples

- Initialise audit policies at the root directory

  <%= config.bin %> <%= command.id %> -o MyTargetOrg

- Initialise audit config at custom directory with preset

  <%= config.bin %> <%= command.id %> -o MyTargetOrg -d my_dir -p loose

# success.classification-summary

Initialised %s %s at %s.

# success.policy-summary

Initialised "%s" policy with %s rule(s) at %s.
