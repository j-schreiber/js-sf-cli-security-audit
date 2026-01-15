export const PERMISSION_SETS_QUERY =
  'SELECT Name,Label,IsCustom,NamespacePrefix FROM PermissionSet WHERE IsOwnedByProfile = FALSE AND NamespacePrefix = NULL';
