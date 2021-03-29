# Project Report
### The Zendesk Product Security Challenge

The following features are implemented in this project.

#### 1. Input sanitization and validation
The form inputs (signup and login) allow for any characters to be entered. The input is not sanitized client- or server-side. However, the input is validated server-side according to the naming and password rules below. Input is only accepted into the server database if validated.

Username (following GitHub's username rules):
- Contains only alphanumeric characters or hyphens.
- Cannot have multiple consecutive hyphens.
- Cannot begin or end with a hyphen.
- Max length of 39 chars.

Password (based on NIST guidelines):
- A minimum of 8 characters.
- A maximum of 64 characters (self-imposed).
- At least 1 digit.
- At least 1 lowercase letter.
- At least 1 uppercase letter.
- At least 1 special character.

#### 2. Password hashed
Passwords are salted and hashed (SHA256) using the `werkzeug.security` library before being stored in the
server database.

#### 3. Prevention of timing attacks
Passwords are verified with the hashed password in the server database using the `werkzeug.security` library,
namely the `check_password_hash(pwhash, password)` method. However, I could not find documentation which
claims that the method performs comparison in constant time. Although, there is another method
`safe_str_cmp(a, b)` which performs comparison in constant time.

#### 4. Logging
Logging is provided by the built-in `logging` library in Python 3. Logs are stored in a file called
`project.log`.

#### 5. CSRF prevention
CSRF tokens from the server are implemented using the `flask_wtf.csrf` library.

#### 6. Multi factor authentication
MFA is currently not implemented.

#### 7. Password reset / forget password mechanism
Password reset is currently not implemented.

#### 8. Account lockout
Rate limiting is implemented for login attempts. A username has a maximum of 3 password attempts every 30 seconds before
an account (username) lockout for a maximum of 30 seconds. Note that this introduces a possibility of denial-of-service
by the server caused by an attacker, as the attacker only needs to attempt 3 logins with a username before that
username is temporarily locked out.

#### 9. Cookie
A cookie called "cookie" is returned to the browser when visiting the site.

#### 10. HTTPS
HTTPS is currently not implemented.
    
#### 11. Known password check
Known password check is currently not implemented.
