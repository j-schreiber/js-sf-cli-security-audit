import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { Messages } from '@salesforce/core';
import Policies from '../../../libs/policies/policies.js';
import PolicySet from '../../../libs/policies/policySet.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.init');

export type OrgAuditInitResult = {
  policies: PolicySet;
};

export default class OrgAuditInit extends SfCommand<OrgAuditInitResult> {
  public static readonly summary = messages.getMessage('summary');
  public static readonly description = messages.getMessage('description');
  public static readonly examples = messages.getMessages('examples');

  public static readonly flags = {
    'target-org': Flags.requiredOrg({
      summary: messages.getMessage('flags.target-org.summary'),
      char: 'o',
      required: true,
    }),
    'output-dir': Flags.directory({
      required: false,
      char: 'd',
      summary: messages.getMessage('flags.output-dir.summary'),
      default: 'policies',
    }),
  };

  public async run(): Promise<OrgAuditInitResult> {
    const { flags } = await this.parse(OrgAuditInit);
    // eslint-disable-next-line sf-plugin/get-connection-with-version
    const policies = await Policies.initialize(flags['target-org'].getConnection());
    this.writeResults(policies, flags['output-dir']);
    return { policies };
  }

  private writeResults(policies: PolicySet, outputDir: string): void {
    const writeResult = Policies.write(policies, outputDir);
    if (policies.userPermissions.length > 0) {
      this.logSuccess(
        messages.getMessage('success.policy-summary', [
          policies.userPermissions?.length ?? 0,
          writeResult.paths['userPermissions'],
        ])
      );
    }
    if (policies.customPermissions.length > 0) {
      this.logSuccess(
        messages.getMessage('success.policy-summary', [
          policies.customPermissions?.length ?? 0,
          writeResult.paths['customPermissions'],
        ])
      );
    }
  }
}
