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
  "SELECT Id,Username,UserType FROM User WHERE IsActive = TRUE AND UserType IN ('Standard') LIMIT 2000";
export const ACTIVE_USERS_DETAILS_QUERY =
  "SELECT Id,Username,Profile.Name,CreatedDate,LastLoginDate FROM User WHERE IsActive = TRUE AND UserType IN ('Standard') LIMIT 2000";

// DYNAMIC QUERIES
export const buildPermsetAssignmentsQuery = (userIds: string[]): string =>
  `${USERS_PERMSET_ASSIGNMENTS_QUERY} AND AssigneeId IN (${userIds.map((userId) => `'${userId}'`).join(',')})`;

export const buildLoginHistoryQuery = (daysToAnalayse?: number): string =>
  daysToAnalayse
    ? `${USERS_LOGIN_HISTORY_QUERY} WHERE LoginTime >= LAST_N_DAYS:${daysToAnalayse} GROUP BY LoginType,Application,UserId`
    : `${USERS_LOGIN_HISTORY_QUERY} GROUP BY LoginType,Application,UserId`;

// PATHS
export const RETRIEVE_CACHE = path.join('.jsc', 'retrieves');

// BASE QUERIES
const USERS_LOGIN_HISTORY_QUERY =
  'SELECT LoginType,Application,UserId,COUNT(Id)LoginCount,MAX(LoginTime)LastLogin FROM LoginHistory';
const USERS_PERMSET_ASSIGNMENTS_QUERY =
  'SELECT AssigneeId,PermissionSet.Name FROM PermissionSetAssignment WHERE PermissionSet.IsOwnedByProfile = FALSE AND PermissionSet.NamespacePrefix = NULL';
