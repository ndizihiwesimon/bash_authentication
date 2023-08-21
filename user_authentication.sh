#!/bin/bash
## to be updated to match your settings
PROJECT_HOME="."
credentials_file="$PROJECT_HOME/data/credentials.txt"
logged_in_session=".login_session.dat"


# Function to prompt for credentials
get_credentials() {
    read -p 'Username: ' user
    read -rs -p 'Password: ' pass
    echo
}

generate_salt() {
    openssl rand -hex 8
    return 0
}

## function for hashing
hash_password() {
    # arg1 is the password
    # arg2 is the salt
    password=$1
    salt=$2
    # we are using the sha256 hash for this.
    echo -n "${password}${salt}" | sha256sum | awk '{print $1}'
    return 0
}
register_admin_user(){

    read -p 'Enter Username: ' username
    read -p 'Enter Full Name: ' full_name
    read -p  "Enter Role (Normal or Salesperson or Admin): " role
    read -rs -p 'Enter Password: ' password
    echo " "
    read -rs -p 'Confirm Password: ' password1

if [ $password != $password1 ]; then

    echo 'Passwords do not match please try again!'
    return 0

elif  grep -qi "^$username:" "$credentials_file" ; then
    echo -e "\n$username already registered please log in!"

else
    register_credentials "$username" "$password" "$full_name" "$role"
fi

}

register_user() {

if [ -f $logged_in_session ]; then
    username=$(awk -F, '{print $1}' $logged_in_session)
    echo -e "\n A user ($username) is logged in, log out and register"
    return 0
fi
    read -p 'Enter Username: ' username
    read -p 'Enter Full Name: ' full_name
    read -rs -p 'Enter Password: ' password
    echo " "
    read -rs -p 'Confirm Password: ' password1

if [ $password != $password1 ]; then

    echo 'Passwords do not match please try again!'
    return 0

# elif [ -f $logged_in_session ]; then
#     username=$(awk -F, '{print $1}' $logged_in_session)
#     echo -e "\n A user ($username) is logged in, log out and register"

elif  grep -qi "^$username:" "$credentials_file" ; then
    echo -e "\n$username already registered please log in!"

else
    register_credentials "$username" "$password" "$full_name" 
fi

}


login(){
# Check if the username is in the db txt file 
# if it is there log the user in with a added line in the login_session file containing username and type
# if it is not there prompt the user to register first


if [ -f $logged_in_session ]; then
    username=$(awk -F, '{print $1}' $logged_in_session)
    echo -e "\n logged in as ($username)"
    return 0
fi

read -p "Enter Username: " username
read -s -p "Enter Password: " password

## first retrieve the salt
matched_user=$(grep -i "^$username:" "$credentials_file")

salt=$(echo "$matched_user" | awk -F':' '{print $3}')

## then hash the password with the salt
hashed_pwd=$(hash_password $password $salt)

if  ! grep -qi "^$username:" "$credentials_file" ; then
    echo "Username not found please register"

# elif [ -f $logged_in_session ]; then
#     username=$(awk -F, '{print $1}' $logged_in_session)
#     echo -e "\n A user ($username) is already logged in"

elif ! grep -qi "^$username:$hashed_pwd" "$credentials_file"; then
    echo -e "\nPassword incorrect please try again"
    echo "$hashed_pwd"

else
    matched_username=$(grep -i "^$username:" "$credentials_file")
    role=$(echo "$matched_username" | awk -F ':' '{print $5}')
    user_cred="$username,$role"
    echo "$user_cred" > "$logged_in_session"
    echo -e "\nLogin successful"
    # awk -v search="$matched_username" -F':' '$0 ~ search {sub(/:[^:]*$/, ":1"); print}' "$credentials_file" > tmpfile && mv tmpfile "$credentials_file"
    sed -i "/$matched_username/ s/:\([^:]*\)$/:1/" "$credentials_file"

    # echo $role

    if [ "$role" == "Admin" ] ; then
        admin_menu
    fi
fi
}

admin_menu(){

echo -e "\nHello Admin welcome! Please select an option"

echo "1. Register a user"
echo "2. Logout"

read -p "Enter your choice: " choice_selection

if [[ "$choice_selection" != [1-2] ]]; then

echo "Wrong selection please try again with a number between [1-2]"

elif  [ "$choice_selection" == 1 ]; then
    register_admin_user

elif  [ "$choice_selection" == 2 ]; then
    logout
        

fi


}

check_existing_username(){
    username=$1
    ## verify if a username is already included in the credentials file
}

## function to add new credentials to the file
register_credentials() {
    # arg1 is the username
    # arg2 is the password
    # arg3 is the fullname of the user
    # arg4 (optional) is the role. Defaults to "normal"

    username=$1
    password=$2
    fullname=$3
    ## call the function to check if the username exists
    # check_existing_username $username
    #TODO: if it exists, safely fails from the function.
    
    ## retrieve the role. Defaults to "normal" if the 4th argument is not passed
    #  sets the value to Normal if no other option is provided
    role="${4:-Normal}"
    ## check if the role is valid. Should be either normal, salesperson, or admin

    ## first generate a salt
    salt=`generate_salt`
    ## then hash the password with the salt
    hashed_pwd=`hash_password $password $salt`
    is_logged_in=0
    ## append the line in the specified format to the credentials file (see below)
    user_cred="$username:$hashed_pwd:$salt:$fullname:$role:$is_logged_in"
    echo "$user_cred" >> "$credentials_file"
    ## username:hash:salt:fullname:role:is_logged_in
    echo -e "\nSUCCESS!"
    echo -e "\nHi $username, thank you for registering please log in!"
}

# Function to verify credentials
verify_credentials() {
    ## arg1 is username
    ## arg2 is password
    username=$1
    password=$2
    ## retrieve the stored hash, and the salt from the credentials file
    # if there is no line, then return 1 and output "Invalid username"

    ## compute the hash based on the provided password
    
    ## compare to the stored hash
    ### if the hashes match, update the credentials file, override the .logged_in file with the
    ### username of the logged in user

    ### else, print "invalid password" and fail.
}

logout() {
    #TODO: check that the .logged_in file is not empty # if the file exists and is not empty, read its content to retrieve the username
    # of the currently logged in user
username=$(awk -F, '{print $1}' $logged_in_session)
matched_username=$(grep -i "^$username:" "$credentials_file")
sed -i "/$matched_username/ s/:\([^:]*\)$/:0/" "$credentials_file"

# awk -v search="$matched_username" -F':' '$0 ~ search {sub(/:[^:]*$/, ":0"); print}' "$credentials_file" > tmpfile && mv tmpfile "$credentials_file"

# Delete login file
rm $logged_in_session
echo -e "\nYou have been logged out!"

return 130

# then delete the existing .logged_in file and update the credentials file by changing the last field to 0
}

## Create the menu for the application
# at the start, we need an option to login, self-register (role defaults to normal)
# and exit the application.

# After the user is logged in, display a menu for logging out. # if the user is also an admin, add an option to create an account using the 
# provided functions.

# Main script execution starts here
while :
do

if [ -f $logged_in_session ]; then
    username=$(awk -F, '{print $1}' $logged_in_session) || echo ""
    echo -e "\n\t\tLogged in as ($username)"

    # # matched_username=$(grep -i "^$username:" "$logged_in_session")
    # role=$(grep -qi "Admin" $logged_in_session)
    # echo $role
    if  grep -qi "Admin" "$logged_in_session" ; then
        admin_menu
    fi
fi
echo -e "\nWelcome to the authentication system."
echo "Select an option:"
echo "1. Login"
echo "2. Register"
echo "3. Logout"
echo "4. Close and exit the Program"

read -p "Enter your choice: " choice_selection

if [[ "$choice_selection" != [1-4] ]]; then

echo "Wrong selection please try again with a number between [1-4]"

elif  [ "$choice_selection" == 1 ]; then
    login

elif  [ "$choice_selection" == 2 ]; then
    register_user
    
elif  [ "$choice_selection" == 3 ]; then
    logout

elif  [ "$choice_selection" == 4 ]; then
    exit 130
fi

done

#### BONUS
#1. Implement a function to delete an account from the file