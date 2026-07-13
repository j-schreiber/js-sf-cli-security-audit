import RuleRegistry from '../ruleRegistry.js';
import { AuditRunConfig } from '../definitions.js';
import { AuditContext } from '../context.types.js';
import { PolicyConfig } from '../shape/schema.js';
import { ObjectDefinition, Objects } from '../../../../salesforce/index.js';
import Policy, { ResolveEntityResult } from './../policy.js';

export default class ObjectsPolicy extends Policy<ObjectDefinition> {
  public constructor(public config: PolicyConfig, public auditConfig: AuditRunConfig, registry: RuleRegistry) {
    super('objects', config, auditConfig, registry);
  }

  protected async resolveEntities(context: AuditContext): Promise<ResolveEntityResult<ObjectDefinition>> {
    const objectsRepo = new Objects(context.targetOrgConnection);
    objectsRepo.addListener('entityresolve', (statusEvt) => this.updateResolveState(statusEvt));
    const objects = await objectsRepo.resolve();
    return { resolvedEntities: Object.fromEntries(objects.entries()), ignoredEntities: [] };
  }
}
