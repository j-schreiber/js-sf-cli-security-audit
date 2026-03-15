import { joinToSoqlIN } from '../../utils.js';

export const ACTIVE_USERS_DETAILS_QUERY =
  "SELECT Id,Username,Profile.Name,CreatedDate,LastLoginDate,IsActive FROM User WHERE IsActive = TRUE AND UserType IN ('Standard')";
export const ALL_USERS_DETAILS_QUERY =
  "SELECT Id,Username,Profile.Name,CreatedDate,LastLoginDate,IsActive FROM User WHERE UserType IN ('Standard')";

// DYNAMIC QUERIES
export const buildPermsetAssignmentsQuery = (userIds: string[]): string =>
  `${USERS_PERMSET_ASSIGNMENTS_QUERY} AND AssigneeId IN (${userIds.map((userId) => `'${userId}'`).join(',')})`;

export const buildScopedLoginHistoryQuery = (userIds: string[], daysToAnalayse?: number): string => {
  const groupBy = 'LoginType,Application,UserId';
  const where = daysToAnalayse
    ? `UserId IN (${joinToSoqlIN(userIds)}) AND LoginTime >= LAST_N_DAYS:${daysToAnalayse}`
    : `UserId IN (${joinToSoqlIN(userIds)})`;
  return `${USERS_LOGIN_HISTORY_QUERY} WHERE ${where} GROUP BY ${groupBy}`;
};

// BASE QUERIES
const USERS_LOGIN_HISTORY_QUERY =
  'SELECT LoginType,Application,UserId,COUNT(Id)LoginCount,MAX(LoginTime)LastLogin FROM LoginHistory';
const USERS_PERMSET_ASSIGNMENTS_QUERY =
  'SELECT AssigneeId,PermissionSet.Name FROM PermissionSetAssignment WHERE PermissionSet.IsOwnedByProfile = FALSE AND PermissionSet.NamespacePrefix = NULL';
