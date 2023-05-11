# Add SecureToken  to Logged-In User

Adds SecureToken to currently logged-in user. Prompts for password of SecureToken admin (gets SecureToken Admin Username from Jamf Pro script parameter) and logged-in user.

This workflow is required to authorize programmatically-created user accounts (that were not already explicitly given a SecureToken) to enable or use FileVault and unlock disk encryption on APFS-formatted startup volumes.

## Credits

- `sysadminctl` SecureToken syntax discovered and formalized in [MacAdmins Slack](https://macadmins.slack.com) #filevault.

## Fork Options

- `delete` 'check_securetoken_logged_in_user' function.
- `add` 'securetoken_remove' function.
- `osascript` menu.
- `add or remove` securetoken via sysadminctl & fdesetup.
- `fdesetup` via expect 'FdeExpect' function.
- `add` exit loop condition if unable to remove or add SecureToken 10 attempts.
- `move` password retreive via function 'GetPass'
