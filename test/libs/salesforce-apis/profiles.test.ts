import { expect } from 'chai';
import AuditTestContext, { parseProfileFromFile } from '../../mocks/auditTestContext.js';
import { Profiles } from '../../../src/libs/core/salesforce-apis/index.js';

describe('profiles resolve', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('resolves all profiles that exist on the org without metadata', async () => {
    // Act
    const repo = new Profiles($$.targetOrgConnection);
    const profiles = await repo.resolve();

    // Assert
    expect(profiles.size).to.equal(3);
    for (const prof of profiles.values()) {
      expect(prof.metadata).to.be.undefined;
    }
  });

  it('resolves all profiles that exist on the org with metadata', async () => {
    // Act
    const repo = new Profiles($$.targetOrgConnection);
    const profiles = await repo.resolve({ withMetadata: true });

    // Assert
    expect(profiles.size).to.equal(2);
    expect(profiles.get('System Administrator')?.metadata).to.deep.contain(
      parseProfileFromFile('admin-profile-with-metadata')
    );
    expect(profiles.get('Standard User')?.metadata).to.deep.contain(
      parseProfileFromFile('standard-profile-with-metadata')
    );
  });

  it('filters specific profiles by name in options', async () => {
    // Act
    const repo = new Profiles($$.targetOrgConnection);
    const profiles = await repo.resolve({ filterNames: ['System Administrator', 'Standard User'] });

    // Assert
    expect(profiles.size).to.equal(2);
    expect(profiles.has('System Administrator')).to.be.true;
    expect(profiles.has('Standard User')).to.be.true;
  });
});
