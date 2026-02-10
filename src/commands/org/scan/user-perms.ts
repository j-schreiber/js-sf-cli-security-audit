import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { Messages } from '@salesforce/core';
import { PermissionScanResult, QuickScanResult } from '../../../libs/quick-scan/types.js';
import UserPermissionScanner, {
  EntityScanStatus,
  PermissionNormalized,
  PermissionNotFound,
  ScanStatusEvent,
} from '../../../libs/quick-scan/userPermissionScanner.js';
import { capitalize } from '../../../utils.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'org.scan.user-perms');

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
    'deep-scan': Flags.boolean({
      summary: messages.getMessage('flags.deep-scan.summary'),
      description: messages.getMessage('flags.deep-scan.description'),
      char: 'd',
    }),
    'include-inactive': Flags.boolean({
      summary: messages.getMessage('flags.include-inactive.summary'),
      description: messages.getMessage('flags.include-inactive.description'),
      char: 'i',
      dependsOn: ['deep-scan'],
    }),
  };

  public async run(): Promise<OrgUserPermScanResult> {
    const { flags } = await this.parse(OrgUserPermScan);
    const scanner = new UserPermissionScanner();

    scanner.on('progress', this.reportProgress);
    scanner.on('permissionNotFound', this.reportWarning);
    scanner.on('permissionNormalized', this.reportNormalisation);

    const result = await scanner.quickScan({
      targetOrg: flags['target-org'].getConnection(flags['api-version']),
      permissions: flags.name,
      deepScan: flags['deep-scan'],
      includeInactive: flags['include-inactive'],
    });
    this.print(result);
    return result;
  }

  private reportProgress = (event: ScanStatusEvent): void => {
    if (event.status === 'Pending') {
      this.spinner.start('Scanning');
    }
    const counters: string[] = [];
    Object.entries(event).forEach(([propName, entityStatus]) => {
      if (isEntityStatus(entityStatus)) {
        counters.push(`${capitalize(propName)} (${entityStatus.resolved!}/${entityStatus.total!})`);
      }
    });
    this.spinner.status = counters.join(' | ');
    if (event.status === 'Completed') {
      this.spinner.stop();
      this.logSuccess(
        messages.getMessage('success.scanned-entities-count', [event.profiles.total, event.permissionSets.total])
      );
      this.log();
    }
  };

  private reportWarning = (event: PermissionNotFound): void => {
    this.warn(messages.createWarning('PermissionNotFound', [event.permissionName]));
  };

  private reportNormalisation = (event: PermissionNormalized): void => {
    this.info(messages.createInfo('PermissionNameNormalised', [event.input, event.normalized]));
  };

  private print(result: QuickScanResult): void {
    this.printSummary(result);
    Object.entries(result.permissions).forEach(([permName, permResult]) => {
      this.printPermissionResults(permName, permResult);
      this.printUserAssignments(permName, permResult.users);
    });
  }

  private printSummary(result: QuickScanResult): void {
    const data: Array<{ permissionName: string; profiles: number; permissionSets: number; users?: number }> = [];
    Object.entries(result.permissions).forEach(([permissionName, permResult]) => {
      data.push({
        permissionName,
        profiles: permResult.profiles.length,
        permissionSets: permResult.permissionSets.length,
        ...(permResult.users ? { assignments: permResult.users.length } : undefined),
      });
    });
    if (data.length > 0) {
      this.table({ data, title: '=== Summary ===', titleOptions: { bold: true } });
    }
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

  private printUserAssignments(permName: string, data: PermissionScanResult['users']): void {
    if (!data || data.length === 0) {
      return;
    }
    data.sort((a, b) => {
      const byUser = a.username.localeCompare(b.username);
      if (byUser !== 0) {
        return byUser;
      }
      const byType = b.type.localeCompare(a.type);
      if (byType !== 0) {
        return byType;
      }
      return a.source.localeCompare(b.source);
    });
    this.table({ title: `${permName} (Assignments)`, data });
  }
}

export function isEntityStatus(cls: unknown): cls is EntityScanStatus {
  return (cls as EntityScanStatus).total !== undefined && (cls as EntityScanStatus).resolved !== undefined;
}
