import fs from 'node:fs';
import { assert } from 'chai';
import { execCmd } from '@salesforce/cli-plugins-testkit';

/**
 * Attempt to fix the recurring, non-deterministic failure of NamedOrgNotFoundError
 * in NUTs: For some reason, the NUTs tests occasionally fail. Instead of building
 * my own pipeline, I'll try to manually set auth in test before hooks.
 */
export function fixDevHubAuth(): void {
  assert.isDefined(process.env.TESTKIT_JWT_KEY);
  assert.isDefined(process.env.TESTKIT_JWT_CLIENT_ID);
  assert.isDefined(process.env.TESTKIT_HUB_USERNAME);
  const keyFile = './server.key';
  fs.writeFileSync(keyFile, process.env.TESTKIT_JWT_KEY);
  execCmd(
    `sf org login jwt --client-id ${process.env.TESTKIT_JWT_CLIENT_ID} --jwt-key-file ${keyFile} --username ${process.env.TESTKIT_HUB_USERNAME} --set-default-dev-hub`,
    { ensureExitCode: 0 }
  ).jsonOutput?.result;
}
