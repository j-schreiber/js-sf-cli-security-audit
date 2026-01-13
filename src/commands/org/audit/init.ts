import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { Messages } from '@salesforce/core';
import AuditConfig from '../../../libs/conf-init/auditConfig.js';
import {
  AuditRunConfig,
  AuditRunConfigClassifications,
  AuditRunConfigPolicies,
  extractEntities,
  isPolicyConfig,
} from '../../../libs/core/file-mgmt/schema.js';
import { AuditInitPresets } from '../../../libs/conf-init/presets.js';
import { capitalize } from '../../../utils.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.init');

export type OrgAuditInitResult = AuditRunConfig;

const presetFlag = Flags.custom<AuditInitPresets>({
  char: 'p',
  summary: messages.getMessage('flags.preset.summary'),
  description: messages.getMessage('flags.preset.description'),
  options: Object.values(AuditInitPresets),
  default: AuditInitPresets.strict,
})();

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
    preset: presetFlag,
    'api-version': Flags.orgApiVersion(),
  };

  public async run(): Promise<OrgAuditInitResult> {
    const { flags } = await this.parse(OrgAuditInit);
    const auditConfig = await AuditConfig.init(flags['target-org'].getConnection(flags['api-version']), {
      targetDir: flags['output-dir'],
      preset: flags.preset,
    });
    this.printResults(auditConfig);
    return auditConfig;
  }

  private printResults(config: AuditRunConfig): void {
    this.printClassifications(config.classifications);
    this.printPolicies(config.policies);
  }

  private printClassifications(classifications: AuditRunConfigClassifications): void {
    Object.entries(classifications).forEach(([key, def]) => {
      const records = extractEntities(def);
      if (records) {
        const recordsCount = Object.keys(records).length;
        if (recordsCount > 0) {
          this.logSuccess(
            messages.getMessage('success.classification-summary', [recordsCount ?? 0, key, def.filePath])
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
              capitalize(name),
              Object.keys(def.content.rules).length ?? 0,
              def.filePath,
            ])
          );
        }
      }
    });
  }
}
