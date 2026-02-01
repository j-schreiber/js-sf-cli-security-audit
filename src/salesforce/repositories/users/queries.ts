export const ACTIVE_USERS_DETAILS_QUERY =
  "SELECT Id,Username,Profile.Name,CreatedDate,LastLoginDate,IsActive FROM User WHERE IsActive = TRUE AND UserType IN ('Standard') LIMIT 2000";

// DYNAMIC QUERIES
export const buildPermsetAssignmentsQuery = (userIds: string[]): string =>
  `${USERS_PERMSET_ASSIGNMENTS_QUERY} AND AssigneeId IN (${userIds.map((userId) => `'${userId}'`).join(',')})`;

export const buildLoginHistoryQuery = (daysToAnalayse?: number): string =>
  daysToAnalayse
    ? `${USERS_LOGIN_HISTORY_QUERY} WHERE LoginTime >= LAST_N_DAYS:${daysToAnalayse} GROUP BY LoginType,Application,UserId`
    : `${USERS_LOGIN_HISTORY_QUERY} GROUP BY LoginType,Application,UserId`;

// BASE QUERIES
const USERS_LOGIN_HISTORY_QUERY =
  'SELECT LoginType,Application,UserId,COUNT(Id)LoginCount,MAX(LoginTime)LastLogin FROM LoginHistory';
const USERS_PERMSET_ASSIGNMENTS_QUERY =
  'SELECT AssigneeId,PermissionSet.Name FROM PermissionSetAssignment WHERE PermissionSet.IsOwnedByProfile = FALSE AND PermissionSet.NamespacePrefix = NULL';
