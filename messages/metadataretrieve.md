# error.FailedToRetrieveComponent

Failed to retrieve the following metadata. This is most likely an error on Salesforce side:

%s

# error.FailedToRetrieveComponent.actions

Check if the metadata actually exists on your org. If you believe this is an error, please open a ticket and describe how to reproduce this:

https://github.com/j-schreiber/js-sf-cli-security-audit/issues/new

# warning.NotAllOauthTokenReturned

The org has %s oauth tokens, but only %s were retrieved. Results may be incomplete.

# warning.TooManyUsersIncreaseLimit

The org has %s total users, but the current limit is %s. Oauth tokens may be missing. You can increase this limit by setting the SAE_MAX_USERS_LIMIT environment variable.

# warning.TooManyActiveUsersIncreaseLimit

The org has %s total active users, but the current limit is %s. Permissions and login history may be missing. You can increase this limit by setting the SAE_MAX_USERS_LIMIT environment variable.
