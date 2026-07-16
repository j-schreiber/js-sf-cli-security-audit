import { expect, assert } from 'chai';
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
    expect(objects.size).to.equal(6);
    expect(objects).keys([
      'Account',
      'MyCustomObject1__c',
      'MyCustomObject2__c',
      'MyCustomObject3__c',
      'RecordActnSelItemExtrc',
      'SharingRulesOnlyObject__c',
    ]);
  });

  it('emits accurate entity resolve statistics during lifecycle', async () => {
    // Act
    const listener = $$.context.SANDBOX.stub();
    const repo = new Objects($$.targetOrgConnection);
    repo.addListener('entityresolve', listener);
    await repo.resolve();

    // Assert
    expect(listener.args.flat()).to.deep.equal([
      { resolved: 0, total: 0 },
      { resolved: 0, total: 5 },
      { resolved: 0, total: 6 },
      { resolved: 6, total: 6 },
    ]);
  });

  it('indicates origin of object def based on original API call', async () => {
    // Act
    const repo = new Objects($$.targetOrgConnection);
    const objects = await repo.resolve();

    // Assert
    const obj1 = objects.get('MyCustomObject1__c');
    assert.isDefined(obj1);
    expect(obj1).to.deep.contain({
      isSharingControllable: true,
      hasEntityDefinition: true,
      hasObjectMetadata: true,
      externalSharing: 'Private',
      internalSharing: 'Read',
    });
    const obj2 = objects.get('SharingRulesOnlyObject__c');
    assert.isDefined(obj2);
    expect(obj2).to.deep.contain({
      isSharingControllable: true,
      hasEntityDefinition: false,
      hasObjectMetadata: false,
      externalSharing: 'Unknown',
      internalSharing: 'Unknown',
    });
  });
});
