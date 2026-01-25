import fs from 'node:fs';
import { assert } from 'chai';
import { AuthFields, AuthInfo } from '@salesforce/core';

/**
 * This shouldn't be needed, but apparently it is. Occasionally, NUT tests
 * fail in CI context (preferrably on Sundays, need to investigate if this
 * is somehow related).
 *
 * Manually creates auth files for the DevHub from JWT env-params, before
 * the TestSession.create() is executed.
 */
export async function fixDevHubAuthFromJWT(): Promise<AuthFields> {
  assert.isDefined(process.env.TESTKIT_JWT_KEY);
  assert.isDefined(process.env.TESTKIT_JWT_CLIENT_ID);
  assert.isDefined(process.env.TESTKIT_HUB_USERNAME);
  assert.isDefined(process.env.TESTKIT_HUB_INSTANCE);
  const keyFile = './server.key';
  fs.writeFileSync(keyFile, process.env.TESTKIT_JWT_KEY);
  const oauthOptions = {
    clientId: process.env.TESTKIT_JWT_CLIENT_ID,
    privateKeyFile: keyFile,
    loginUrl: process.env.TESTKIT_HUB_INSTANCE,
    username: process.env.TESTKIT_HUB_USERNAME,
  };
  const authInfo = await AuthInfo.create(oauthOptions);
  await authInfo.save();
  await authInfo.handleAliasAndDefaultSettings({
    setDefault: false,
    setDefaultDevHub: true,
  });
  return authInfo.getFields(true);
}
