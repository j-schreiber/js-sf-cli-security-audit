import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { Messages } from '@salesforce/core';
import AuditRun from '../../../libs/policies/auditRun.js';
import AuditRunConfig, {
  AuditRunClassifications,
  AuditRunPolicies,
  isClassification,
  isPolicy,
} from '../../../libs/policies/interfaces/auditRunConfig.js';

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
    const auditConfig = await AuditRun.initialiseNewConfig(flags['target-org'].getConnection(flags['api-version']), {
      directoryPath: flags['output-dir'],
    });
    this.printResults(auditConfig);
    return auditConfig;
  }

  private printResults(config: AuditRunConfig): void {
    this.printClassifications(config.classifications);
    this.printPolicies(config.policies);
  }

  private printClassifications(classifications: AuditRunClassifications): void {
    Object.values(classifications).forEach((def) => {
      if (isClassification(def)) {
        const perms = def.content.permissions ? Object.entries(def.content.permissions) : [];
        if (perms.length > 0) {
          this.logSuccess(
            messages.getMessage('success.perm-classification-summary', [perms.length ?? 0, def.filePath])
          );
        }
      }
    });
  }

  private printPolicies(policies: AuditRunPolicies): void {
    Object.entries(policies).forEach(([name, def]) => {
      if (isPolicy(def)) {
        const vals = def.getValues() ? Object.entries(def.getValues()) : [];
        if (def.filePath) {
          this.logSuccess(messages.getMessage('success.policy-summary', [name, vals.length ?? 0, def.filePath]));
        }
      }
    });
  }
}
