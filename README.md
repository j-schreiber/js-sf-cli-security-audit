# @j-schreiber/sf-cli-security-audit

> This plugin is still in beta and under active development. Command signatures may be subject to change.

For an in-depth documentation that goes beyond command signatures and explains the core concepts, design decisions, and a variety of use cases [see our Wiki](https://github.com/j-schreiber/js-sf-cli-security-audit/wiki).

# Installation

To build from source, follow these steps

```bash
git clone https://github.com/j-schreiber/js-sf-cli-security-audit
mkdir sf-cli-security-audit
yarn && yarn build
sf plugins link .
```

To install the latest version from NPM

```bash
sf plugins install @j-schreiber/sf-cli-security-audit
```

# Contribute

Contributers are welcome! Please reach out on [Linkedin](https://www.linkedin.com/in/jannis-schreiber/) or via [Email](mailto:info@lietzau-consulting.de).

# Documentation

<!-- commands -->

- [`sf org audit init`](#sf-org-audit-init)
- [`sf org audit run`](#sf-org-audit-run)
- [`sf org scan user-perms`](#sf-org-scan-user-perms)

## `sf org audit init`

Initialises classifications and policies for a security audit.

```
USAGE
  $ sf org audit init -o <value> [--json] [--flags-dir <value>] [-d <value>] [-p strict|loose|none] [--api-version
    <value>]

FLAGS
  -d, --output-dir=<value>   Directory where the audit config is initialised. If not set, the root directory will be
                             used.
  -o, --target-org=<value>   (required) Target org to export permissions, profiles, users, etc.
  -p, --preset=<option>      [default: strict] Select a preset to initialise permission classifications (risk levels).
                             <options: strict|loose|none>
      --api-version=<value>  Override the api version used for api requests made by this command

GLOBAL FLAGS
  --flags-dir=<value>  Import flag values from a directory.
  --json               Format output as json.

DESCRIPTION
  Initialises classifications and policies for a security audit.

  Exports permissions (standard and custom), permission sets, profiles, users, etc from the target org. All
  classifications are initialised with sane defaults that you can customize later.

EXAMPLES
  Initialise audit policies at the root directory

    $ sf org audit init -o MyTargetOrg

  Initialise audit config at custom directory with preset

    $ sf org audit init -o MyTargetOrg -d my_dir -p loose

FLAG DESCRIPTIONS
  -p, --preset=strict|loose|none  Select a preset to initialise permission classifications (risk levels).

    The selected preset is applied before any other default mechanisms (such as template configs). This means, values
    from a selected template override the preset. Consult the documentation to learn more about the rationale behind the
    default risk levels. The risk levels interact with the configured preset on profiles and permission sets and
    essentially control, if a permission is allowed in a certain profile / permission set.
```

_See code: [src/commands/org/audit/init.ts](https://github.com/j-schreiber/js-sf-cli-security-audit/blob/v0.6.0/src/commands/org/audit/init.ts)_

## `sf org audit run`

Audit your org.

```
USAGE
  $ sf org audit run -o <value> [--json] [--flags-dir <value>] [-d <value>] [--api-version <value>]

FLAGS
  -d, --source-dir=<value>   Location of the audit config.
  -o, --target-org=<value>   (required) The org that is audited.
      --api-version=<value>  Override the api version used for api requests made by this command

GLOBAL FLAGS
  --flags-dir=<value>  Import flag values from a directory.
  --json               Format output as json.

DESCRIPTION
  Audit your org.

  Loads a given audit config (a set of classifications and policies) and runs the policies against the target org. The
  audit run creates a comprehensive report that lists all executed policies and all resolved entities that were audited.

EXAMPLES
  Audit the org MyTargetOrg with the config in configs/prod

    $ sf org audit run -o MyTargetOrg -d configs/prod
```

_See code: [src/commands/org/audit/run.ts](https://github.com/j-schreiber/js-sf-cli-security-audit/blob/v0.6.0/src/commands/org/audit/run.ts)_

## `sf org scan user-perms`

Performs a quick scan to check permission sets and profiles for user permissions.

```
USAGE
  $ sf org scan user-perms -n <value>... -o <value> [--json] [--flags-dir <value>] [--api-version <value>]

FLAGS
  -n, --name=<value>...      (required) One or more permissions to be scanned.
  -o, --target-org=<value>   (required) The target org to scan.
      --api-version=<value>  Override the api version used for api requests made by this command

GLOBAL FLAGS
  --flags-dir=<value>  Import flag values from a directory.
  --json               Format output as json.

DESCRIPTION
  Performs a quick scan to check permission sets and profiles for user permissions.

  The quick scan does not need an audit config and does not create reports. The target org is scanned "in memory" and
  simply outputs information, where the searched user permissions

EXAMPLES
  $ sf org scan user-perms

FLAG DESCRIPTIONS
  -n, --name=<value>...  One or more permissions to be scanned.

    You can specify any valid user permission on your org, such as "AuthorApex", "CustomizeApplication" or "ViewSetup".
    If you are unsure what permissions are available on your org, initialise a new audit config and check the created
    userPermissions.yml.
```

_See code: [src/commands/org/scan/user-perms.ts](https://github.com/j-schreiber/js-sf-cli-security-audit/blob/v0.6.0/src/commands/org/scan/user-perms.ts)_

<!-- commandsstop -->

# Development

Make sure the dev plugin is installed

```bash
sf plugins install @salesforce/plugin-dev
```

Generate a new command (initialises messages, tests, etc)

```bash
sf dev generate command -n my:command:name
```
