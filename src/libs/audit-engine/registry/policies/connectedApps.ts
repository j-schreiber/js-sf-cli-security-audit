import RuleRegistry from '../ruleRegistry.js';
import { ConnectedApp, ConnectedApps } from '../../../../salesforce/index.js';
import { AuditRunConfig } from '../definitions.js';
import { AuditContext } from '../context.types.js';
import { PolicyConfig } from '../shape/schema.js';
import Policy, { ResolveEntityResult } from './../policy.js';

export default class ConnectedAppsPolicy extends Policy<ConnectedApp> {
  public constructor(public config: PolicyConfig, public auditConfig: AuditRunConfig, registry: RuleRegistry) {
    super('users', config, auditConfig, registry);
  }

  protected async resolveEntities(context: AuditContext): Promise<ResolveEntityResult<ConnectedApp>> {
    const resolvedEntities: Record<string, ConnectedApp> = {};
    const appsRepo = new ConnectedApps(context.targetOrgConnection);
    appsRepo.addListener('entityresolve', (resolveEvt) => this.emit('entityresolve', resolveEvt));
    const apps = await appsRepo.resolve({ withOAuthToken: true });
    for (const app of apps.values()) {
      resolvedEntities[app.name] = app;
    }
    return { resolvedEntities, ignoredEntities: [] };
  }
}
