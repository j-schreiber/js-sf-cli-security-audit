/* eslint-disable camelcase */
import { expect } from 'chai';
import Sinon, { SinonSandbox } from 'sinon';
import { MultiStageOutput } from '@oclif/multi-stage-output';
import AuditRunMultiStageOutput, {
  AuditRunData,
  EXECUTE_RULES,
  RESOLVE_POLICIES,
} from '../../src/ux/auditRunMultiStage.js';
import { AuditRun, PolicyConfig } from '../../src/libs/audit-engine/index.js';

const PROFILES_CONFIG: PolicyConfig = {
  enabled: true,
  rules: {
    Rule1: { enabled: true },
    Rule2: { enabled: true },
    Rule3: { enabled: false },
  },
};
const PERMSETS_CONFIG: PolicyConfig = {
  enabled: true,
  rules: { Rule1: { enabled: true }, Rule2: { enabled: true } },
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
      policies: { profiles: PROFILES_CONFIG },
    });
    testInstance.startPolicyResolve(auditRun);
    testInstance.startRuleExecution(auditRun);

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
    expect(uxStub?.updateData.callCount).to.equal(2);
  });

  it('does not initialise disabled policies as substage', () => {
    // Act
    const profilesConfig = structuredClone(PROFILES_CONFIG);
    profilesConfig.enabled = false;
    const auditRun = new AuditRun({
      policies: { profiles: profilesConfig },
    });
    testInstance.startPolicyResolve(auditRun);

    // Assert
    // policy is disabled, no stage specific blocks for resolve & rules are created
    expect(testInstance.stageSpecificBlocks).to.deep.equal([]);
  });

  it('updates policy resolve sub block with entity statistics', () => {
    // Act
    const auditRun = new AuditRun({
      policies: { profiles: PROFILES_CONFIG, permissionSets: PERMSETS_CONFIG },
    });
    testInstance.startPolicyResolve(auditRun);
    auditRun.emit('entityresolve-profiles', { total: 12, resolved: 0 });
    auditRun.emit('entityresolve-permissionSets', { total: 20, resolved: 0 });
    auditRun.emit('entityresolve-profiles', { total: 12, resolved: 4 });
    auditRun.emit('entityresolve-profiles', { total: 12, resolved: 12 });
    auditRun.emit('entityresolve-permissionSets', { total: 20, resolved: 20 });

    // Assert
    expect(uxStub?.updateData.callCount).to.equal(6);
    expect(uxStub?.updateData.args.flat()[1]).to.deep.equal({
      policies: {
        profiles: { total: 12, resolved: 0 },
      },
    });
    expect(uxStub?.updateData.args.flat()[2]).to.deep.equal({
      policies: {
        permissionSets: { total: 20, resolved: 0 },
        profiles: { total: 12, resolved: 0 },
      },
    });
  });

  it('handles incomplete entity resolve result from audit run', () => {
    // Act
    const auditRun = new AuditRun({
      policies: { profiles: PROFILES_CONFIG },
    });
    testInstance.startPolicyResolve(auditRun);
    auditRun.emit('entityresolve-profiles', { total: 12 });

    // Assert
    expect(uxStub?.updateData.callCount).to.equal(2);
    expect(uxStub?.updateData.args.flat()[1]).to.deep.equal({
      policies: {
        profiles: { total: 12, resolved: 0 },
      },
    });
  });

  it('does not count disabled rules in executed rules summary', () => {
    // Act
    const auditRun = new AuditRun({
      policies: { profiles: PROFILES_CONFIG },
      classifications: {},
    });
    testInstance.startPolicyResolve(auditRun);
    testInstance.startRuleExecution(auditRun);

    // Assert
    expect(testInstance.stageSpecificBlocks.length).to.equal(2);
    expect(testInstance.stageSpecificBlocks[1]).to.deep.contain({
      type: 'message',
      stage: EXECUTE_RULES,
    });
    const ruleBlockText = testInstance.stageSpecificBlocks[1].get({} as AuditRunData);
    // no rules from test data actually resolve successfully
    expect(ruleBlockText).to.equal('0 rule(s) for Profiles');
    expect(uxStub?.updateData.callCount).to.equal(2);
  });
});
