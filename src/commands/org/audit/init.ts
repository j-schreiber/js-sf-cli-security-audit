import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { Messages } from '@salesforce/core';
import AuditConfig from '../../../libs/policies/initialisation/auditConfig.js';
import {
  AuditRunConfig,
  AuditRunConfigClassifications,
  AuditRunConfigPolicies,
  isPermissionsConfig,
  isPolicyConfig,
} from '../../../libs/config/audit-run/schema.js';

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
    'api-version': Flags.orgApiVersion(),
  };

  public async run(): Promise<OrgAuditInitResult> {
    const { flags } = await this.parse(OrgAuditInit);
    const auditConfig = await AuditConfig.init(flags['target-org'].getConnection(flags['api-version']), {
      targetDir: flags['output-dir'],
    });
    this.printResults(auditConfig);
    return auditConfig;
  }

  private printResults(config: AuditRunConfig): void {
    this.printClassifications(config.classifications);
    this.printPolicies(config.policies);
  }

  private printClassifications(classifications: AuditRunConfigClassifications): void {
    Object.values(classifications).forEach((def) => {
      if (isPermissionsConfig(def)) {
        const perms = def.content.permissions ? Object.entries(def.content.permissions) : [];
        if (perms.length > 0) {
          this.logSuccess(
            messages.getMessage('success.perm-classification-summary', [perms.length ?? 0, def.filePath])
          );
        }
      }
    });
  }

  private printPolicies(policies: AuditRunConfigPolicies): void {
    Object.entries(policies).forEach(([name, def]) => {
      if (isPolicyConfig(def)) {
        if (def.filePath) {
          this.logSuccess(
            messages.getMessage('success.policy-summary', [
              name,
              Object.keys(def.content.rules).length ?? 0,
              def.filePath,
            ])
          );
        }
      }
    });
  }
}
