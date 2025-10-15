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

## `sf org audit init`

Initialises classifications and policies for a security audit.

```
USAGE
  $ sf org audit init -o <value> [--json] [--flags-dir <value>] [-d <value>] [--api-version <value>]

FLAGS
  -d, --output-dir=<value>   Directory where the audit config is initialised. If not set, the root directory will be
                             used.
  -o, --target-org=<value>   (required) Target org to export permissions, profiles, users, etc.
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
```

_See code: [src/commands/org/audit/init.ts](https://github.com/j-schreiber/js-sf-cli-security-audit/blob/v0.1.0/src/commands/org/audit/init.ts)_

## `sf org audit run`

Audit your org.

```
USAGE
  $ sf org audit run -o <value> -d <value> [--json] [--flags-dir <value>] [--api-version <value>]

FLAGS
  -d, --source-dir=<value>   (required) Location of the audit config.
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

_See code: [src/commands/org/audit/run.ts](https://github.com/j-schreiber/js-sf-cli-security-audit/blob/v0.1.0/src/commands/org/audit/run.ts)_

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
