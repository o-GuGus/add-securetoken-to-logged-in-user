#!/bin/sh

###
#
#            Name:  s_add-or-remove_securetoken-to-logged-in-user
#     Description:  
#                   
#          Author:  Fork of Mario Panighetti & New version of Guillaume Gosselin
#         Created:  2023-05-04
#   Last Modified:  2023-05-05
#         Version:  5.0.0
#
###



########## variable-ing ##########



# Jamf Pro script parameter: "SecureToken Admin Username"
# A local administrator account with SecureToken access.
secureTokenAdmin="${5}"
loggedInUser=$(/usr/bin/stat -f%Su "/dev/console")
macOSVersionMajor=$(/usr/bin/sw_vers -productVersion | /usr/bin/awk -F . '{print $1}')
macOSVersionMinor=$(/usr/bin/sw_vers -productVersion | /usr/bin/awk -F . '{print $2}')
macOSVersionBuild=$(/usr/bin/sw_vers -productVersion | /usr/bin/awk -F . '{print $3}')
# Need default password values so the initial logic loops will properly fail when validating passwords. You can store the actual credentials here to skip password prompts entirely, but for security reasons this is not generally recommended. Please don't actually use "foo" as a password, for so many reasons.
secureTokenAdminPass="foo"
loggedInUserPass="foo"
passwordPrompt="foo"



########## function-ing ##########



# Exits with error if any required Jamf Pro arguments are undefined.
check_jamf_pro_arguments () {
	if [ -z "$secureTokenAdmin" ]; then
		echo "❌ ERROR: Undefined Jamf Pro argument, unable to proceed."
		exit 74
	fi
}


# Exits if macOS version predates the use of SecureToken functionality.
check_macos_version () {
	# Exit if macOS < 10.
	if [ "$macOSVersionMajor" -lt 10 ]; then
		echo "macOS version ${macOSVersionMajor} predates the use of SecureToken functionality, no action required."
		exit 0
		# Exit if macOS 10 < 10.13.4.
	elif [ "$macOSVersionMajor" -eq 10 ]; then
		if [ "$macOSVersionMinor" -lt 13 ]; then
			echo "macOS version ${macOSVersionMajor}.${macOSVersionMinor} predates the use of SecureToken functionality, no action required."
			exit 0
		elif [ "$macOSVersionMinor" -eq 13 ] && [ "$macOSVersionBuild" -lt 4 ]; then
			echo "macOS version ${macOSVersionMajor}.${macOSVersionMinor}.${macOSVersionBuild} predates the use of SecureToken functionality, no action required."
			exit 0
		fi
	fi
}


# Exits if root is the currently logged-in user, or no logged-in user is detected.
check_logged_in_user () {
	if [ "$loggedInUser" = "root" ] || [ -z "$loggedInUser" ]; then
		echo "Nobody is logged in."
		exit 0
	fi
}


# Exits with error if $secureTokenAdmin does not have SecureToken (unless running macOS 10.15 or later, in which case exit with explanation).
check_securetoken_admin () {
	if /usr/sbin/sysadminctl -secureTokenStatus "$secureTokenAdmin" 2>&1 | /usr/bin/grep -q "DISABLED" ; then
		if [ "$macOSVersionMajor" -gt 10 ] || [ "$macOSVersionMajor" -eq 10 ] && [ "$macOSVersionMinor" -gt 14 ]; then
			echo "⚠️ Neither ${secureTokenAdmin} nor ${loggedInUser} has a SecureToken, but in macOS 10.15 or later, a SecureToken is automatically granted to the first user to enable FileVault (if no other users have SecureToken), so this may not be necessary. Try enabling FileVault for ${loggedInUser}. If that fails, see what other user on the system has SecureToken, and use its credentials to grant SecureToken to ${loggedInUser}."
			exit 0
		else
			echo "❌ ERROR: ${secureTokenAdmin} does not have a valid SecureToken, unable to proceed. Please update Jamf Pro policy to target another admin user with SecureToken."
			exit 1
		fi
	else
		echo "✅ Verified ${secureTokenAdmin} has SecureToken."
	fi
}


# Prompts for local password.
local_account_password_prompt () {
	passwordPrompt=$(/usr/bin/osascript -e "set user_password to text returned of (display dialog \"${2}\" default answer \"\" with hidden answer)")
	if [ -z "$passwordPrompt" ]; then
		echo "❌ ERROR: A password was not entered for ${1}, unable to proceed. Please rerun policy; if issue persists, a manual SecureToken add will be required to continue."
		exit 1
	fi
}


# Validates provided password.
local_account_password_validation () {
	if /usr/bin/dscl "/Local/Default" authonly "${1}" "${2}" > "/dev/null" 2>&1; then
		echo "✅ Password successfully validated for ${1}."
	else
		echo "❌ ERROR: Failed password validation for ${1}. Please reenter the password when prompted."
	fi
}


# Adds SecureToken to target user.
securetoken_add () {
attempts=0
until /usr/sbin/sysadminctl -secureTokenStatus "$loggedInUser" 2>&1 | /usr/bin/grep -q "ENABLED"; do
	/usr/sbin/sysadminctl \
	-adminUser "${1}" \
	-adminPassword "${2}" \
	-secureTokenOn "${3}" \
	-password "${4}"
	
	# Verify successful SecureToken add.
	secureTokenCheck=$(/usr/sbin/sysadminctl -secureTokenStatus "${3}" 2>&1)
	if echo "$secureTokenCheck" | /usr/bin/grep -q "DISABLED"; then
		echo "❌ ERROR: Failed to add SecureToken to ${3}. Please rerun policy; if issue persists, a manual SecureToken add will be required to continue."
		exit 126
	elif echo "$secureTokenCheck" | /usr/bin/grep -q "ENABLED"; then
		echo "✅ Successfully added SecureToken to ${3}."
	else
		echo "❌ ERROR: Unexpected result, unable to proceed. Please rerun policy; if issue persists, a manual SecureToken add will be required to continue."
		exit 1
	fi
((attempts++))
if [ "$attempts" -eq 10 ]; then
echo "❌ ERROR: Unable to add SecureToken to ${3} after 10 attempts."
exit 1
fi
done
}


# Adds SecureToken to target user.
securetoken_remove () {
attempts=0
until /usr/sbin/sysadminctl -secureTokenStatus "$loggedInUser" 2>&1 | /usr/bin/grep -q "DISABLED"; do
	/usr/sbin/sysadminctl \
	-adminUser "${1}" \
	-adminPassword "${2}" \
	-secureTokenOff "${3}" \
	-password "${4}"

	# Verify successful SecureToken remove.
	secureTokenCheck=$(/usr/sbin/sysadminctl -secureTokenStatus "${3}" 2>&1)
	if echo "$secureTokenCheck" | /usr/bin/grep -q "ENABLED"; then
		echo "❌ ERROR: Failed to remove SecureToken to ${3}. Please rerun policy; if issue persists, a manual SecureToken add will be required to continue."
        exit 126
	elif echo "$secureTokenCheck" | /usr/bin/grep -q "DISABLED"; then
		echo "✅ Successfully remove SecureToken to ${3}."
	else
		echo "❌ ERROR: Unexpected result, unable to proceed. Please rerun policy; if issue persists, a manual SecureToken add will be required to continue."
		exit 1
	fi
((attempts++))
if [ "$attempts" -eq 10 ]; then
echo "❌ ERROR: Unable to remove SecureToken to ${3} after 10 attempts."
exit 1
fi
done
}

# Add or Remove FDESETUP to target user.
function FdeExpect() {
	echo "[START] expect function"
	echo "[Launch] sudo fdesetup $fde1 $fde2 $loggedInUser"
	/usr/bin/expect  << 'EOF'
		set timeout -1
		exp_internal -f /tmp/fdesetup_add.log 0
		spawn sudo fdesetup $env(fde1) $env(fde2) $env(loggedInUser)

expect {
	"Error" {
		send_user "Term found, Error, exiting...\n";exit 1
	}
	"Enter the user name" {
		send -- "$env(secureTokenAdmin)\r"
	}
	"Enter the password for user" {
		send -- "$env(secureTokenAdminPass)\r"
	}
	"Enter the password for the added user" {
		send -- "$env(loggedInUserPass)\r"
	}
	timeout {
		send_user "Timeout occurred.\n"
		exit 1
	}
	eof {
		send_user "End of output.\n"
		exit 0
	}
}

expect {
	"Error" {
		send_user "Term found, Error, exiting...\n";exit 1
	}
	"Enter the user name" {
		send -- "$env(secureTokenAdmin)\r"
	}
	"Enter the password for user" {
		send -- "$env(secureTokenAdminPass)\r"
	}
	"Enter the password for the added user" {
		send -- "$env(loggedInUserPass)\r"
	}
	timeout {
		send_user "Timeout occurred.\n"
		exit 1
	}
	eof {
		send_user "End of output.\n"
		exit 0
	}
}

expect {
	"Error" {
		send_user "Term found, Error, exiting...\n";exit 1
	}
	"Enter the user name" {
		send -- "$env(secureTokenAdmin)\r"
	}
	"Enter the password for user" {
		send -- "$env(secureTokenAdminPass)\r"
	}
	"Enter the password for the added user" {
		send -- "$env(loggedInUserPass)\r"
	}
	timeout {
		send_user "Timeout occurred.\n"
		exit 1
	}
	eof {
		send_user "End of output.\n"
		exit 0
	}
}

EOF
	echo "[END] expect function"
    echo "✅ Fdesetup is ${fde1} for ${loggedInUser}."
}


# GetPass
function GetPass() {

	# Get $secureTokenAdmin password.
	echo "Get $secureTokenAdmin password"
	until /usr/bin/dscl "/Local/Default" authonly "$secureTokenAdmin" "$secureTokenAdminPass" > "/dev/null" 2>&1; do
		local_account_password_prompt "$secureTokenAdmin" "Please enter ADMIN password for ${secureTokenAdmin}."
		secureTokenAdminPass="$passwordPrompt"
		local_account_password_validation "$secureTokenAdmin" "$secureTokenAdminPass"
	done
	
	# Get $loggedInUser password.
    echo "Get $loggedInUser password"
	until /usr/bin/dscl "/Local/Default" authonly "$loggedInUser" "$loggedInUserPass" > "/dev/null" 2>&1; do
		local_account_password_prompt "$loggedInUser" "Please enter USER password for ${loggedInUser}."
		loggedInUserPass="$passwordPrompt"
		local_account_password_validation "$loggedInUser" "$loggedInUserPass"
	done
    
 # Export variables for expect
	export secureTokenAdmin
	export secureTokenAdminPass
	export loggedInUser
	export loggedInUserPass
}


########## main process ##########


# Check script prerequisites.
check_jamf_pro_arguments
check_macos_version
check_logged_in_user
check_securetoken_admin

# Afficher le menu osascript pour que l'utilisateur choisisse entre 'remove' et 'add'
choice=$(osascript <<EOF
    set options to {"remove", "add"}
    choose from list options with prompt "Do you want to remove or add a secureToken for $loggedInUser ?"
    set chosen to item 1 of result
    return chosen
EOF
)

# Vérifier le choix de l'utilisateur et exporter la variable correspondante
if [[ "$choice" == "remove" ]]; then
    # GetPass
    GetPass
	# Remove Fdesetup using provided credentials.
    fde1="remove" && fde2="-user" && export fde1 && export fde2 && FdeExpect
    # Remove SecureToken using provided credentials.
	securetoken_remove "$secureTokenAdmin" "$secureTokenAdminPass" "$loggedInUser" "$loggedInUserPass"

elif [[ "$choice" == "add" ]]; then
    # GetPass
    GetPass
	# Add Fdesetup using provided credentials.
	fde1="add" && fde2="-usertoadd" && export fde1 && export fde2 && FdeExpect
    # Add SecureToken using provided credentials.
	securetoken_add "$secureTokenAdmin" "$secureTokenAdminPass" "$loggedInUser" "$loggedInUserPass"
else
    echo "Invalid choice"
    exit 1
fi

exit 0