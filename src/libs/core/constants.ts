import path from 'node:path';

// QUERIES
export const CUSTOM_PERMS_QUERY = 'SELECT Id,MasterLabel,DeveloperName FROM CustomPermission';
export const PROFILES_QUERY =
  'SELECT Profile.Name,Profile.UserType,IsCustom FROM PermissionSet WHERE IsOwnedByProfile = TRUE';
export const PERMISSION_SETS_QUERY =
  'SELECT Name,Label,IsCustom,NamespacePrefix FROM PermissionSet WHERE IsOwnedByProfile = FALSE AND NamespacePrefix = NULL';
export const CONNECTED_APPS_QUERY = 'SELECT Name,OptionsAllowAdminApprovedUsersOnly FROM ConnectedApplication';
export const OAUTH_TOKEN_QUERY = 'SELECT User.Username,UseCount,AppName FROM OauthToken';
export const ACTIVE_USERS_QUERY =
  "SELECT Id,Username,UserType FROM User WHERE IsActive = TRUE AND UserType IN ('Guest','Standard') LIMIT 2000";
export const ACTIVE_USERS_DETAILS_QUERY =
  "SELECT Id,Username,Profile.Name FROM User WHERE IsActive = TRUE AND UserType IN ('Guest','Standard') LIMIT 2000";
export const USERS_LOGIN_HISTORY_QUERY = '';
export const USERS_PERMSET_ASSIGNMENTS_QUERY =
  'SELECT AssigneeId,PermissionSet.Name FROM PermissionSetAssignment WHERE PermissionSet.IsOwnedByProfile = FALSE AND PermissionSet.NamespacePrefix = NULL';

// DYNAMIC QUERIES
export const buildPermsetAssignmentsQuery = (userIds: string[]): string =>
  `${USERS_PERMSET_ASSIGNMENTS_QUERY} WHERE AssigneeId IN (${userIds.map((userId) => `'${userId}'`).join(',')})`;

// PATHS
export const RETRIEVE_CACHE = path.join('.jsc', 'retrieves');
