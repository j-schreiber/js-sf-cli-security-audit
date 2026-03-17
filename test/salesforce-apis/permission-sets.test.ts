import { expect } from 'chai';
import AuditTestContext from '../mocks/auditTestContext.js';
import { PermissionSets } from '../../src/salesforce/index.js';
import { parsePermSetFromFile } from '../mocks/testHelpers.js';

describe('permission sets resolve', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    $$.mocks.mockPermissionSets('resolvable-permission-sets');
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('resolves all permission sets that exist on the org without metadata', async () => {
    // Act
    const repo = new PermissionSets($$.targetOrgConnection);
    const permSets = await repo.resolve();

    // Assert
    expect(permSets.size).to.equal(7);
    for (const ps of permSets.values()) {
      expect(ps.metadata).to.be.undefined;
    }
  });

  it('resolves custom permission sets only when option is set', async () => {
    // Act
    const repo = new PermissionSets($$.targetOrgConnection);
    const permSets = await repo.resolve({ isCustomOnly: true });

    // Assert
    expect(permSets.size).to.equal(6);
    for (const ps of permSets.values()) {
      expect(ps.isCustom).to.be.true;
    }
  });

  it('resolves all permission sets that exist on the org with metadata option', async () => {
    // Act
    const repo = new PermissionSets($$.targetOrgConnection);
    const permSets = await repo.resolve({ withMetadata: true });

    // Assert
    expect(permSets.size).to.equal(7);
    for (const ps of permSets.values()) {
      expect(ps.metadata).not.to.be.undefined;
    }
    const resolvedPermset = permSets.get('Test_Admin_Permission_Set_1');
    const expectedMetadata = parsePermSetFromFile('Test_Admin_Permission_Set_1');
    expect(resolvedPermset?.metadata).to.deep.contain(expectedMetadata);
  });

  it('only returns permission sets that exist on target org if filter is set', async () => {
    // Act
    const repo = new PermissionSets($$.targetOrgConnection);
    const permSets = await repo.resolve({
      filterNames: ['Test_Permset_Invalid', 'Test_Admin_Permission_Set_1', 'Test_Standard_User_Permission_Set_2'],
    });

    // Assert
    expect(permSets.size).to.equal(2);
    expect(permSets.has('Test_Admin_Permission_Set_1')).to.be.true;
    expect(permSets.has('Test_Standard_User_Permission_Set_2')).to.be.true;
  });
});
