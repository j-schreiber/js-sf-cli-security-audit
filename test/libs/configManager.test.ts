import { Messages } from '@salesforce/core';
import { assert, expect } from 'chai';
import AuditTestContext from '../mocks/auditTestContext.js';
import AuditConfigProvider from '../../src/libs/conf-init/manager.js';
import { AuditRunConfig } from '../../src/libs/audit-engine/index.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);

const BLANK_CONFIG: AuditRunConfig = {
  acceptedRisks: {},
  inventory: {},
  controls: {},
  shape: {},
  policies: {},
};

describe('config manager', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('inits full inventory when its missing in existing config', async () => {
    // Act
    const result = await AuditConfigProvider.manageInventory($$.targetOrgConnection, {
      type: 'profiles',
      refresh: true,
      prune: false,
      config: BLANK_CONFIG,
    });

    // Assert
    assert.isDefined(result.updatedConfig.inventory.profiles);
    const newProfiles = ['Custom Profile', 'System Administrator', 'Standard User'];
    expect(result.updatedConfig.inventory.profiles).to.have.all.keys(newProfiles);
    expect(result.addedEntities).to.deep.equal(newProfiles);
    expect(result.removedEntities).to.deep.equal([]);
  });

  it('completes inventory when entity is missing in existing config', async () => {
    // Arrange
    const TEST_CONFIG = {
      ...BLANK_CONFIG,
      inventory: { profiles: { 'Custom Profile': { role: 'Preexisting Role' } } },
    };

    // Act
    const result = await AuditConfigProvider.manageInventory($$.targetOrgConnection, {
      type: 'profiles',
      refresh: true,
      prune: false,
      config: TEST_CONFIG,
    });

    // Assert
    assert.isDefined(result.updatedConfig.inventory.profiles);
    expect(result.updatedConfig.inventory.profiles).to.have.all.keys([
      'Custom Profile',
      'System Administrator',
      'Standard User',
    ]);
    expect(result.updatedConfig.inventory.profiles['Custom Profile']).to.deep.equal({ role: 'Preexisting Role' });
    expect(result.addedEntities).to.deep.equal(['System Administrator', 'Standard User']);
    expect(result.removedEntities).to.deep.equal([]);
  });

  it('prunes obsolete entities in config that are not in target org', async () => {
    // Arrange
    const TEST_CONFIG = {
      ...BLANK_CONFIG,
      inventory: {
        profiles: {
          'Invalid Profile': { role: 'Preexisting Role' },
          'Custom Profile': { role: 'Preexisting Role' },
        },
      },
    };
    // Act
    const result = await AuditConfigProvider.manageInventory($$.targetOrgConnection, {
      type: 'profiles',
      refresh: false,
      prune: true,
      config: TEST_CONFIG,
    });

    // Assert
    assert.isDefined(result.updatedConfig.inventory.profiles);
    expect(result.updatedConfig.inventory.profiles).to.have.all.keys(['Custom Profile']);
    expect(result.addedEntities).to.deep.equal([]);
    expect(result.removedEntities).to.deep.equal(['Invalid Profile']);
  });
});
