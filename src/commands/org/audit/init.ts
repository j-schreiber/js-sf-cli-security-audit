import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { Messages } from '@salesforce/core';
import AuditConfig from '../../../libs/conf-init/auditConfig.js';
import { AuditInitPresets } from '../../../libs/conf-init/init.types.js';
import { capitalize } from '../../../utils.js';
import { saveAuditConfig } from '../../../libs/audit-engine/index.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.audit.init');

type AuditConfigSaveResult = ReturnType<typeof saveAuditConfig>;
export type OrgAuditInitResult = AuditConfigSaveResult;

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
      preset: flags.preset,
    });
    const saveResult = saveAuditConfig(flags['output-dir'], auditConfig);
    this.printResults(saveResult);
    return saveResult;
  }

  private printResults(config: AuditConfigSaveResult): void {
    this.printClassifications(config.classifications);
    this.printPolicies(config.policies);
  }

  private printClassifications(classifications: AuditConfigSaveResult['classifications']): void {
    Object.entries(classifications).forEach(([key, def]) => {
      if (def.totalEntities > 0) {
        this.logSuccess(messages.getMessage('success.classification-summary', [def.totalEntities, key, def.filePath]));
      }
    });
  }

  private printPolicies(policies: AuditConfigSaveResult['policies']): void {
    Object.entries(policies).forEach(([name, def]) => {
      if (def.filePath) {
        this.logSuccess(
          messages.getMessage('success.policy-summary', [
            capitalize(name),
            Object.keys(def.content.rules).length ?? 0,
            def.filePath,
          ])
        );
      }
    });
  }
}
