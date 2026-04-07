import { joinToSoqlIN } from '../../utils.js';

export const CONNECTED_APPS_QUERY = 'SELECT Id,Name,OptionsAllowAdminApprovedUsersOnly FROM ConnectedApplication';
export const ALL_EXISTING_USER_IDS = 'SELECT Id FROM User';
export const EXTERNAL_CLIENT_APPS_QUERY =
  'SELECT Id,MasterLabel,DeveloperName,DistributionState FROM ExternalClientApplication';
export const EXTERNAL_APPS_OAUTH_POLICY =
  'SELECT ExternalClientApplicationId,PermittedUsersPolicyType FROM ExtlClntAppOauthPlcyCnfg';
export const OAUTH_TOKEN_QUERY =
  'SELECT User.Username,UseCount,LastUsedDate,AppName,AppMenuItem.ApplicationId FROM OauthToken';
export const COUNT_TOKEN_QUERY = 'SELECT COUNT() FROM OauthToken';

export function formatCountSoql(userIds: string[]): string {
  return `${COUNT_TOKEN_QUERY} WHERE UserId IN (${joinToSoqlIN(userIds)})`;
}

export function formatTokenSoql(userIds: string[]): string {
  return `${OAUTH_TOKEN_QUERY} WHERE UserId IN (${joinToSoqlIN(userIds)})`;
}
