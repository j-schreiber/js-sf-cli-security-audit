import fs from 'node:fs';
import { assert } from 'chai';
import { AuthFields, AuthInfo, AuthRemover, SfError } from '@salesforce/core';

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
  const privateKeyFile = './server.key';
  fs.writeFileSync(privateKeyFile, process.env.TESTKIT_JWT_KEY);
  const authInfo = await createOrOverwriteAuthInfo({
    username: process.env.TESTKIT_HUB_USERNAME,
    isDevHub: true,
    oauth2Options: {
      clientId: process.env.TESTKIT_JWT_CLIENT_ID,
      loginUrl: process.env.TESTKIT_HUB_INSTANCE,
      privateKeyFile,
    },
  });
  await authInfo.save();
  await authInfo.handleAliasAndDefaultSettings({
    setDefault: false,
    setDefaultDevHub: true,
  });
  fs.rmSync(privateKeyFile, { force: true });
  return authInfo.getFields(true);
}

async function createOrOverwriteAuthInfo(opts: AuthInfo.Options): Promise<AuthInfo> {
  let authInfo: AuthInfo;
  try {
    authInfo = await AuthInfo.create(opts);
  } catch (error) {
    const err = error as SfError;
    if (err.name === 'AuthInfoOverwriteError') {
      const remover = await AuthRemover.create();
      await remover.removeAuth(opts.username!);
      authInfo = await AuthInfo.create(opts);
    } else {
      throw err;
    }
  }
  return authInfo;
}
