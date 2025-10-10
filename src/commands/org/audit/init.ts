import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { Messages } from '@salesforce/core';
import AuditRun from '../../../libs/policies/auditRun.js';
import AuditRunConfig from '../../../libs/policies/interfaces/auditRunConfig.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.init');

export type OrgAuditInitResult = AuditRunConfig;

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
    const auditConfig = await AuditRun.initialiseNewConfig(flags['target-org'].getConnection('64.0'), {
      directoryPath: flags['output-dir'],
    });
    this.logResults(auditConfig);
    return auditConfig;
  }

  private logResults(config: AuditRunConfig): void {
    const userPerms = config.classifications.userPermissions
      ? Object.entries(config.classifications.userPermissions.content.permissions)
      : [];
    if (userPerms.length > 0) {
      this.logSuccess(
        messages.getMessage('success.perm-classification-summary', [
          userPerms.length ?? 0,
          config.classifications.userPermissions?.filePath,
        ])
      );
    }
    const customPerms = config.classifications.customPermissions
      ? Object.entries(config.classifications.customPermissions.content.permissions)
      : [];
    if (customPerms.length > 0) {
      this.logSuccess(
        messages.getMessage('success.perm-classification-summary', [
          customPerms.length ?? 0,
          config.classifications.customPermissions?.filePath,
        ])
      );
    }
    // if (config.classification.customPermissions.length > 0) {
    //   this.logSuccess(
    //     messages.getMessage('success.perm-classification-summary', [
    //       config.classification.customPermissions?.length ?? 0,
    //       writeResult.paths.customPermissions,
    //     ])
    //   );
    // }
    // if (config.policies.profiles) {
    //   const writtenProfiles = Object.keys(config.policies.profiles.profiles).length;
    //   if (writtenProfiles > 0) {
    //     this.logSuccess(
    //       messages.getMessage('success.profile-policy-summary', [writtenProfiles, writeResult.paths.profilePolicy])
    //     );
    //   }
    // }
    // if (config.policies.permissionSets) {
    //   const writtenPermSets = Object.keys(config.policies.permissionSets.permissionSets).length;
    //   if (writtenPermSets > 0) {
    //     this.logSuccess(
    //       messages.getMessage('success.permset-policy-summary', [
    //         writtenPermSets,
    //         writeResult.paths.permissionSetPolicy,
    //       ])
    //     );
    //   }
    // }
  }
}
