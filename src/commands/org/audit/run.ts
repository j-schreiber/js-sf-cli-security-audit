import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { Interfaces } from '@oclif/core';
import { SfCommand, Flags, StandardColors } from '@salesforce/sf-plugins-core';
import { Messages } from '@salesforce/core';
import { AuditPolicyResult, AuditResult, PolicyRuleExecutionResult } from '../../../libs/audit/types.js';
import AuditRun from '../../../libs/policies/auditRun.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.run');

export type OrgAuditRunResult = AuditResult & {
  filePath: string;
};

type OrgAuditRunFlags = Interfaces.InferredFlags<typeof OrgAuditRun.flags>;

export default class OrgAuditRun extends SfCommand<OrgAuditRunResult> {
  public static readonly summary = messages.getMessage('summary');
  public static readonly description = messages.getMessage('description');
  public static readonly examples = messages.getMessages('examples');

  public static readonly flags = {
    'target-org': Flags.requiredOrg({
      summary: messages.getMessage('flags.target-org.summary'),
      char: 'o',
      required: true,
    }),
    'source-dir': Flags.directory({
      required: true,
      char: 'd',
      summary: messages.getMessage('flags.source-dir.summary'),
    }),
    'api-version': Flags.orgApiVersion(),
  };

  public async run(): Promise<OrgAuditRunResult> {
    const { flags } = await this.parse(OrgAuditRun);
    const auditRun = AuditRun.load(flags['source-dir']);
    const partialResult = await auditRun.execute(flags['target-org'].getConnection(flags['api-version']));
    const result = { orgId: flags['target-org'].getOrgId(), ...partialResult };
    this.printResults(result);
    const filePath = this.writeReport(result, flags);
    return { ...result, filePath };
  }

  private printResults(result: AuditResult): void {
    this.printPoliciesSummary(result);
    Object.entries(result.policies).forEach(([policyName, policyDetails]) => {
      this.printExecutedRulesSummary(policyName, policyDetails);
      this.printRuleViolations(policyDetails.executedRules);
    });
  }

  private printPoliciesSummary(result: AuditResult): void {
    const polSummaries = transposePoliciesToTable(result);
    this.log(`Successfully executed ${polSummaries.length} policies.`);
    if (result.isCompliant) {
      this.logSuccess(messages.getMessage('success.all-policies-compliant'));
      this.log('');
    } else {
      this.log(StandardColors.error(messages.getMessage('summary-non-compliant')));
      this.log('');
    }
    this.table({ data: polSummaries, title: '=== Summary ===', titleOptions: { bold: true } });
  }

  private printExecutedRulesSummary(policyName: string, policyDetails: AuditPolicyResult): void {
    const rulesSummary = transposeExecutedPolicyRules(policyDetails);
    this.table({
      data: rulesSummary,
      title: `--- Executed Rules for ${policyName} ---`,
      titleOptions: { underline: true },
    });
  }

  private printRuleViolations(executedRules: Record<string, PolicyRuleExecutionResult>): void {
    Object.values(executedRules)
      .filter((ruleDetails) => !ruleDetails.isCompliant)
      .forEach((uncompliantRule) => {
        this.table({ data: uncompliantRule.violations, title: `Violations for ${uncompliantRule.ruleName}` });
      });
  }

  private writeReport(result: AuditResult, flags: OrgAuditRunFlags): string {
    const fileName = `report_${flags['target-org'].getOrgId()}_${Date.now()}.json`;
    const fullPath = path.join(flags['source-dir'], fileName);
    writeFileSync(fullPath, JSON.stringify(result, null, 2));
    this.info(messages.getMessage('info.report-file-location', [fullPath]));
    return fullPath;
  }
}

type PolicyResultsSummary = {
  policy: string;
  isCompliant: boolean;
  rulesExecuted: number;
  auditedEntities: number;
};

type ExecutedRulesResultsSummary = {
  rule: string;
  isCompliant: boolean;
  violations: number;
  warnings: number;
  errors: number;
};

function transposePoliciesToTable(result: AuditResult): PolicyResultsSummary[] {
  return Object.entries(result.policies).map(([policyName, policyDetails]) => {
    const rulesExecuted = policyDetails?.executedRules ? Object.keys(policyDetails.executedRules).length : 0;
    return {
      policy: policyName,
      isCompliant: policyDetails.isCompliant,
      rulesExecuted,
      auditedEntities: policyDetails.auditedEntities.length,
    };
  });
}

function transposeExecutedPolicyRules(result: AuditPolicyResult): ExecutedRulesResultsSummary[] {
  return Object.entries(result.executedRules).map(([ruleName, ruleDetails]) => ({
    rule: ruleName,
    isCompliant: ruleDetails.isCompliant,
    violations: ruleDetails.violations.length,
    warnings: ruleDetails.warnings.length,
    errors: ruleDetails.errors.length,
  }));
}
