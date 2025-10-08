import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { Messages } from '@salesforce/core';
import Policies from '../../../libs/policies/policies.js';
import PolicySet from '../../../libs/policies/policySet.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.init');

export type OrgAuditInitResult = PolicySet;

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
      default: '',
    }),
  };

  public async run(): Promise<OrgAuditInitResult> {
    const { flags } = await this.parse(OrgAuditInit);
    // inset of async await, run with listener and log events
    // make "resolve" or smth that allows to paralellise with Promise.all()
    // eslint-disable-next-line sf-plugin/get-connection-with-version
    const auditConfig = await Policies.initialize(flags['target-org'].getConnection());
    this.writeConfigFiles(auditConfig, flags['output-dir']);
    return auditConfig;
  }

  private writeConfigFiles(config: PolicySet, outputDir: string): void {
    const writeResult = Policies.write(config, outputDir);
    if (config.classification.userPermissions.length > 0) {
      this.logSuccess(
        messages.getMessage('success.perm-classification-summary', [
          config.classification.userPermissions?.length ?? 0,
          writeResult.paths.userPermissions,
        ])
      );
    }
    if (config.classification.customPermissions.length > 0) {
      this.logSuccess(
        messages.getMessage('success.perm-classification-summary', [
          config.classification.customPermissions?.length ?? 0,
          writeResult.paths.customPermissions,
        ])
      );
    }
    if (config.policies.profiles) {
      const writtenProfiles = Object.keys(config.policies.profiles.profiles).length;
      if (writtenProfiles > 0) {
        this.logSuccess(
          messages.getMessage('success.profile-policy-summary', [writtenProfiles, writeResult.paths.profilePolicy])
        );
      }
    }
    if (config.policies.permissionSets) {
      const writtenPermSets = Object.keys(config.policies.permissionSets.permissionSets).length;
      if (writtenPermSets > 0) {
        this.logSuccess(
          messages.getMessage('success.permset-policy-summary', [
            writtenPermSets,
            writeResult.paths.permissionSetPolicy,
          ])
        );
      }
    }
  }
}
