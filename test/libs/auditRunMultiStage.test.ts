/* eslint-disable camelcase */
import { expect } from 'chai';
import Sinon, { SinonSandbox } from 'sinon';
import { MultiStageOutput } from '@oclif/multi-stage-output';
import AuditRunMultiStageOutput, {
  AuditRunData,
  EXECUTE_RULES,
  RESOLVE_POLICIES,
} from '../../src/ux/auditRunMultiStage.js';
import AuditRun from '../../src/libs/policies/auditRun.js';
import { ProfilesRiskPreset } from '../../src/libs/core/policy-types.js';

const PROFILES_CONFIG = {
  content: {
    enabled: true,
    rules: { Rule1: { enabled: true }, Rule2: { enabled: true } },
    profiles: { 'Test Profile 1': { preset: ProfilesRiskPreset.DEVELOPER } },
  },
};

const PERMSETS_CONFIG = {
  content: {
    enabled: true,
    rules: { Rule1: { enabled: true }, Rule2: { enabled: true } },
    permissionSets: {
      Test_Perm_Set_1: { preset: ProfilesRiskPreset.DEVELOPER },
      Test_Perm_Set_2: { preset: ProfilesRiskPreset.DEVELOPER },
    },
  },
};

describe('audit run multi stage output', () => {
  const SANDBOX: SinonSandbox = Sinon.createSandbox();
  let uxStub: ReturnType<typeof stubMultiStageUx> | undefined;
  let testInstance: AuditRunMultiStageOutput;

  function stubMultiStageUx(): Sinon.SinonStubbedInstance<MultiStageOutput<AuditRunData>> {
    const stub = SANDBOX.createStubInstance(MultiStageOutput<AuditRunData>);
    SANDBOX.stub(AuditRunMultiStageOutput, 'initUx').returns(stub);
    return stub;
  }

  beforeEach(() => {
    // comment out stub to show the multi-stage output in test terminal
    // this is useful if we experiment with different configs to evaluate
    // the visual appearance without actually running the command
    uxStub = stubMultiStageUx();
    // initialising the instance in setup and calling "stop" in afterEach ensures
    // that the tests don't run endlessly even if ux is not stubbed
    testInstance = AuditRunMultiStageOutput.create({ targetOrg: 'test@example.com', directoryRootPath: 'my_config' });
  });

  afterEach(() => {
    testInstance.finish();
    SANDBOX.restore();
  });

  it('initialises each policy from config as stubstage of resolve and execute', () => {
    // Act
    const auditRun = new AuditRun({
      policies: { Profiles: PROFILES_CONFIG },
      classifications: {},
    });
    testInstance.startPolicyResolve(auditRun);

    // Assert
    expect(testInstance.stageSpecificBlocks.length).to.equal(2);
    expect(testInstance.stageSpecificBlocks[0]).to.deep.contain({
      type: 'dynamic-key-value',
      stage: RESOLVE_POLICIES,
    });
    expect(testInstance.stageSpecificBlocks[1]).to.deep.contain({
      type: 'message',
      stage: EXECUTE_RULES,
    });
    expect(uxStub?.updateData.callCount).to.equal(1);
  });

  it('updates policy resolve sub block with entity statistics', () => {
    // Act
    const auditRun = new AuditRun({
      policies: { Profiles: PROFILES_CONFIG, PermissionSets: PERMSETS_CONFIG },
      classifications: {},
    });
    testInstance.startPolicyResolve(auditRun);
    auditRun.emit('entityresolve-Profiles', { total: 12, resolved: 0 });
    auditRun.emit('entityresolve-PermissionSets', { total: 20, resolved: 0 });
    auditRun.emit('entityresolve-Profiles', { total: 12, resolved: 4 });
    auditRun.emit('entityresolve-Profiles', { total: 12, resolved: 12 });
    auditRun.emit('entityresolve-PermissionSets', { total: 20, resolved: 20 });

    // Assert
    expect(uxStub?.updateData.callCount).to.equal(6);
    expect(uxStub?.updateData.args.flat()[1]).to.deep.equal({
      policies: {
        Profiles: { total: 12, resolved: 0 },
      },
    });
    expect(uxStub?.updateData.args.flat()[2]).to.deep.equal({
      policies: {
        PermissionSets: { total: 20, resolved: 0 },
        Profiles: { total: 12, resolved: 0 },
      },
    });
  });

  it('handles incomplete entity resolve result from audit run', () => {
    // Act
    const auditRun = new AuditRun({
      policies: { Profiles: PROFILES_CONFIG },
      classifications: {},
    });
    testInstance.startPolicyResolve(auditRun);
    auditRun.emit('entityresolve-Profiles', { total: 12 });

    // Assert
    expect(uxStub?.updateData.callCount).to.equal(2);
    expect(uxStub?.updateData.args.flat()[1]).to.deep.equal({
      policies: {
        Profiles: { total: 12, resolved: 0 },
      },
    });
  });
});
