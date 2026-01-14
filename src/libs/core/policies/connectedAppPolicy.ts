import { AuditRunConfig, BasePolicyFileContent } from '../file-mgmt/schema.js';
import { AuditContext } from '../registries/types.js';
import { ConnectedAppsRegistry } from '../registries/connectedApps.js';
import { ConnectedApp, ConnectedApps } from '../../../salesforce/index.js';
import Policy, { ResolveEntityResult } from './policy.js';

export default class ConnectedAppPolicy extends Policy<ConnectedApp> {
  public constructor(
    public config: BasePolicyFileContent,
    public auditConfig: AuditRunConfig,
    registry = ConnectedAppsRegistry
  ) {
    super(config, auditConfig, registry);
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
