# @j-schreiber/sf-cli-security-audit

> This plugin is still in beta and under active development. Command signatures may be subject to change.

# Installation

This plugin is not yet published on NPM. You must check out the repo and link it locally.

```bash
git clone https://...
mkdir sf-cli-security-audit
yarn && yarn build
sf plugins link .
```

# Contribute

Contributers are welcome! Please reach out on [Linkedin](https://www.linkedin.com/in/jannis-schreiber/) or via [Email](mailto:info@lietzau-consulting.de).

# Documentation

<!-- commands -->

- [`sf org audit init`](#sf-org-audit-init)

## `sf org audit init`

Initialises policies for a security audit

```
USAGE
  $ sf org audit init -o <value> [--json] [--flags-dir <value>] [-d <value>]

FLAGS
  -d, --output-dir=<value>  Top level directory, where policies are initialised.
  -o, --target-org=<value>  (required) Target org to check.

GLOBAL FLAGS
  --flags-dir=<value>  Import flag values from a directory.
  --json               Format output as json.

DESCRIPTION
  Initialises policies for a security audit

  Exports all available custom permissions and initialises policies

EXAMPLES
  Initialise audit policies at the root directory

    $ sf org audit init -o MyTargetOrg
```

_See code: [src/commands/org/audit/init.ts](https://github.com/j-schreiber/js-sf-cli-security-audit/blob/v0.1.0/src/commands/org/audit/init.ts)_

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
