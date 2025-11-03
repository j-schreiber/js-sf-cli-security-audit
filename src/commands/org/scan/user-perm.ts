import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { Messages } from '@salesforce/core';
import { PermissionScanResult, QuickScanResult } from '../../../libs/quick-scan/types.js';
import UserPermissionScanner from '../../../libs/quick-scan/userPermissionScanner.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.scan.user-perm');

export type OrgUserPermScanResult = QuickScanResult;

export default class OrgUserPermScan extends SfCommand<OrgUserPermScanResult> {
  public static readonly summary = messages.getMessage('summary');
  public static readonly description = messages.getMessage('description');
  public static readonly examples = messages.getMessages('examples');

  public static readonly flags = {
    name: Flags.string({
      summary: messages.getMessage('flags.name.summary'),
      description: messages.getMessage('flags.name.description'),
      char: 'n',
      multiple: true,
      required: true,
    }),
    'target-org': Flags.requiredOrg({
      summary: messages.getMessage('flags.target-org.summary'),
      char: 'o',
      required: true,
    }),
    'api-version': Flags.orgApiVersion(),
  };

  public async run(): Promise<OrgUserPermScanResult> {
    const { flags } = await this.parse(OrgUserPermScan);
    const result = await UserPermissionScanner.quickScan({
      targetOrg: flags['target-org'].getConnection(flags['api-version']),
      permissions: flags.name,
    });
    this.print(result);
    return result;
  }

  private print(result: QuickScanResult): void {
    this.printSummary(result);
    Object.entries(result).forEach(([permName, permResult]) => {
      this.printPermissionResults(permName, permResult);
    });
  }

  private printSummary(result: QuickScanResult): void {
    const data: Array<{ permissionName: string; profiles: number; permissionSets: number }> = [];
    Object.entries(result).forEach(([permissionName, permResult]) => {
      data.push({
        permissionName,
        profiles: permResult.profiles.length,
        permissionSets: permResult.permissionSets.length,
      });
    });
    this.table({ data, title: '=== Summary ===', titleOptions: { bold: true } });
  }

  private printPermissionResults(permissionName: string, result: PermissionScanResult): void {
    const data: Array<{ entityName: string; type: string }> = [];
    result.profiles.forEach((entityName) => {
      data.push({ entityName, type: 'Profile' });
    });
    result.permissionSets.forEach((entityName) => {
      data.push({ entityName, type: 'Permission Set' });
    });
    if (data.length > 0) {
      this.table({ data, title: permissionName, titleOptions: { underline: true } });
    }
  }
}
