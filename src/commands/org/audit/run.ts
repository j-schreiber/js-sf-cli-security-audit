import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { Messages } from '@salesforce/core';
import ProfilePolicy from '../../../libs/policies/profilePolicy.js';
import PolicySet from '../../../libs/policies/policySet.js';
import { AuditResult } from '../../../libs/audit/types.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.run');

export type OrgAuditRunResult = AuditResult;

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
      summary: messages.getMessage('flags.output-dir.summary'),
    }),
  };

  public async run(): Promise<OrgAuditRunResult> {
    const { flags } = await this.parse(OrgAuditRun);
    const auditConfig = PolicySet.load(flags['source-dir']);
    const profilePolicy = new ProfilePolicy(auditConfig.policies.profiles!);
    const result = await profilePolicy.run({ targetOrgConnection: flags['target-org'].getConnection(), auditConfig });
    return {
      isCompliant: true,
      policies: {
        Profiles: result,
      },
    };
  }
}
