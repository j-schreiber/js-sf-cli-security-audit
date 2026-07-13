import { expect } from 'chai';
import AuditTestContext from '../mocks/auditTestContext.js';
import { Objects } from '../../src/salesforce/index.js';

describe('object definitions resolve', () => {
  const $$ = new AuditTestContext();

  beforeEach(async () => {
    await $$.init();
  });

  afterEach(async () => {
    $$.reset();
  });

  it('resolves all objects that are returned by metadata list command', async () => {
    // Act
    const repo = new Objects($$.targetOrgConnection);
    const objects = await repo.resolve();

    // Assert
    expect(objects.size).to.equal(5);
    expect(objects).keys([
      'Account',
      'MyCustomObject1__c',
      'MyCustomObject2__c',
      'MyCustomObject3__c',
      'RecordActnSelItemExtrc',
    ]);
  });
});
