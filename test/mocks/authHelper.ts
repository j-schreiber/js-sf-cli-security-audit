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
  const authInfo = await AuthInfo.create({
    username: process.env.TESTKIT_HUB_USERNAME,
    isDevHub: true,
    oauth2Options: {
      clientId: process.env.TESTKIT_JWT_CLIENT_ID,
      privateKey: process.env.TESTKIT_JWT_KEY,
      loginUrl: process.env.TESTKIT_HUB_INSTANCE,
    },
  });
  await authInfo.save();
  await authInfo.handleAliasAndDefaultSettings({
    setDefault: false,
    setDefaultDevHub: true,
  });
  return authInfo.getFields(true);
}
