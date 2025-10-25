export const CUSTOM_PERMS_QUERY = 'SELECT Id,MasterLabel,DeveloperName FROM CustomPermission';
export const PROFILES_QUERY =
  'SELECT Profile.Name,Profile.UserType,IsCustom FROM PermissionSet WHERE IsOwnedByProfile = TRUE';
export const PERMISSION_SETS_QUERY =
  'SELECT Name,Label,IsCustom,NamespacePrefix FROM PermissionSet WHERE IsOwnedByProfile = FALSE AND NamespacePrefix = NULL';
export const CONNECTED_APPS_QUERY = 'SELECT Name,OptionsAllowAdminApprovedUsersOnly FROM ConnectedApplication';
export const OAUTH_TOKEN_QUERY = 'SELECT User.Username,UseCount,AppName FROM OauthToken';
