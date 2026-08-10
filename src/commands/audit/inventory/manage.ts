import { SfCommand, Flags } from '@salesforce/sf-plugins-core';
import { Messages } from '@salesforce/core';
import { capitalize } from '../../../utils.js';
import Prompts from '../../../ux/prompts.js';
import {
  AuditConfigShape,
  AuditRunConfig,
  Inventories,
  loadAuditConfig,
  saveAuditConfig,
} from '../../../libs/audit-engine/index.js';
import AuditConfigProvider, { ManageInventoryResult } from '../../../libs/conf-init/manager.js';
import SfConnection from '../../../salesforce/connection.js';

Messages.importMessagesDirectoryFromMetaUrl(import.meta.url);
const messages = Messages.loadMessages('@j-schreiber/sf-cli-security-audit', 'audit.inventory.manage');

type ChoiceValue<T> = {
  short: string;
  disabled: boolean;
  name: string;
  value: T;
  description: string;
};

type ManageOperations = 'refresh' | 'prune';

const WHITESPACE = '   ';

export default class ManageInventory extends SfCommand<ManageInventoryResult> {
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
      required: false,
      char: 'd',
      summary: messages.getMessage('flags.source-dir.summary'),
      default: '',
    }),
    'api-version': Flags.orgApiVersion(),
    verbose: Flags.boolean({ summary: messages.getMessage('flags.verbose.summary'), default: false }),
  };

  public async run(): Promise<ManageInventoryResult> {
    const { flags } = await this.parse(ManageInventory);
    const existingConfig = loadAuditConfig(flags['source-dir']);
    const selectedType = await Prompts.select({
      message: messages.getMessage('ux.choices.inventory-type.prompt'),
      choices: buildInventoryTypeChoices(existingConfig.inventory),
    });
    const selectedOperation = await Prompts.select({
      message: messages.getMessage('ux.choices.operation.prompt'),
      choices: buildOperationChoices(existingConfig.inventory, selectedType),
    });
    const result = await AuditConfigProvider.manageInventory(
      new SfConnection(flags['target-org'].getConnection(flags['api-version'])),
      {
        type: selectedType,
        prune: selectedOperation === 'prune',
        refresh: selectedOperation === 'refresh',
        config: existingConfig,
      }
    );
    saveAuditConfig(flags['source-dir'], result.updatedConfig);
    this.logResults(result, flags.verbose);
    return result;
  }

  private logResults(result: ManageInventoryResult, logVerbose: boolean): void {
    if (logVerbose && result.addedEntities.length > 0) {
      this.table({
        data: result.addedEntities.map((entityName) => ({ [`added${capitalize(result.type)}`]: entityName })),
      });
    }
    if (logVerbose && result.removedEntities.length > 0) {
      this.table({
        data: result.removedEntities.map((entityName) => ({ [`removed${capitalize(result.type)}`]: entityName })),
      });
    }
    this.logSuccess(
      messages.getMessage('ux.summary.completion', [
        result.addedEntities.length,
        result.removedEntities.length,
        capitalize(result.type),
      ])
    );
  }
}

function buildInventoryTypeChoices(existingInventory: AuditRunConfig['inventory']): Array<ChoiceValue<Inventories>> {
  return Object.keys(AuditConfigShape['inventory']['files']).map((value) => {
    const existing = existingInventory[value as Inventories];
    return {
      short: capitalize(value),
      disabled: false,
      name: WHITESPACE + capitalize(value),
      value: value as Inventories,
      description: existing
        ? messages.getMessage('ux.choices.inventory-type.entities-found', [Object.keys(existing).length])
        : messages.getMessage('ux.choices.inventory-type.no-entities-found'),
    };
  });
}

function buildOperationChoices(
  existingInventory: AuditRunConfig['inventory'],
  selectedType: Inventories
): Array<ChoiceValue<ManageOperations>> {
  const selectedExists = existingInventory[selectedType] !== undefined;
  return [
    {
      short: 'Refresh',
      disabled: false,
      name: WHITESPACE + 'Refresh',
      value: 'refresh',
      description: selectedExists
        ? messages.getMessage('ux.choices.refresh.description-existing')
        : messages.getMessage('ux.choices.refresh.description-fresh'),
    },
    {
      short: 'Prune',
      name: WHITESPACE + 'Prune',
      value: 'prune',
      description: messages.getMessage('ux.choices.prune.description'),
      disabled: !selectedExists,
    },
  ];
}
