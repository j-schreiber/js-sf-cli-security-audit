export const CONNECTED_APPS_QUERY = 'SELECT Name,OptionsAllowAdminApprovedUsersOnly FROM ConnectedApplication';
export const ALL_EXISTING_USER_IDS = 'SELECT Id FROM User';
export const OAUTH_TOKEN_QUERY = 'SELECT User.Username,UseCount,AppName FROM OauthToken';
export const COUNT_TOKEN_QUERY = 'SELECT COUNT() FROM OauthToken';

export function formatCountSoql(userIds: string[]): string {
  return `${COUNT_TOKEN_QUERY} WHERE UserId IN (${joinToSoqlIN(userIds)})`;
}

export function formatTokenSoql(userIds: string[]): string {
  return `${OAUTH_TOKEN_QUERY} WHERE UserId IN (${joinToSoqlIN(userIds)})`;
}

function joinToSoqlIN(userIds: string[]): string {
  return userIds.map((id) => `'${id}'`).join(',');
}
