import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { Messages } from '@salesforce/core';
import { AuditResult } from '../../../libs/audit/types.js';
import AuditRun from '../../../libs/policies/auditRun.js';

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
      summary: messages.getMessage('flags.source-dir.summary'),
    }),
  };

  public async run(): Promise<OrgAuditRunResult> {
    const { flags } = await this.parse(OrgAuditRun);
    const auditRun = AuditRun.load(flags['source-dir']);
    const result = await auditRun.execute(flags['target-org'].getConnection('64.0'));
    return result;
  }
}
