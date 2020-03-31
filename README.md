# User REST API

REST API for user management, featuring: creating, retrieving, updating, and removing users; 2FA; email verification; email password reset; account level logging; and server logging.

## TODO

- Send email when creating account [Postmark?](https://postmarkapp.com).
- Send email when requesting a password reset [Postmark?](https://postmarkapp.com).
- JWT Token refreshing
- Device sessions
- [MongoDB TLS](https://docs.mongodb.com/manual/tutorial/configure-ssl/)
- [Rate Limiting](https://blog.risingstack.com/10-best-practices-for-writing-node-js-rest-apis/)
- ? [CSRF Protection](https://github.com/expressjs/csurf)

## Links

- [Security Cheatsheet](https://cheatsheetseries.owasp.org)
- [Security Checklist](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/HTML5_Security_Cheat_Sheet.md)
- [DB Performance](https://www.mongodb.com/blog/post/performance-best-practices-mongodb-data-modeling-and-memory-sizing)
- [MaxMind IP Geolocation](https://github.com/runk/node-maxmind)
- [Self-signed SAN certificate creation](https://stackoverflow.com/a/41366949/11435885)
- [Make Safari accept self-signed certificate](https://stackoverflow.com/questions/47482264/cannot-accept-self-signed-certificate-in-safari-11-to-access-vagrant-homestead)

# API Documentation

Root of the API routes: `/api/v0`.

The API was designed to follow REST guidelines and always return meaningful errors. Status code 500 should never be returned, but is included in the documentation for completeness.

Logging is provided to log requests and responses and features four different levels:

Level | Meaning
--- | ---
DEBUG (1) | Print all types of logged messages during operation.
INFO (2) | Print all but debug types of logged messages during operation.
WARN (3) | Print only warnings and errors during operation.
QUIET (4) | Do not print logged messages (including warnings and errors) during operation.

Account related events like (failed) logins and password requests are logged to the user's personal event log using response middleware:

Event Type | Meaning
--- | ---
*Subject to change* | *Subject to change*
LOGIN_FAIL (1) | Failed login attempt with the user's email address.
LOGIN_SUCCESS (2) | Successful login attempt with the user's email address.
RESET_REQUEST (3) | Password reset email was requested for the user.
RESET_SUCCESS (4) | User's password was reset successfully.
INFORMATION_CHANGE_FAIL (5) | Failed attempt to change the user's account information.
INFORMATION_CHANGE_SUCCESS (6) | Successful attempt to change the user's account information.
EMAIL_VERIFIED (7) | Account email address was verified.
\_2FA_PREPARED (8) | 2FA was prepared for the account to allow the user to link an authenticator mobile application.
\_2FA_ENABLED (9) | 2FA was enabled for the account after a successful token verification.
\_2FA_DISABLED (10) | 2FA was disabled for the account.
\_2FA_FAIL (11) | 2FA token verification request failed.
\_2FA_SUCCESS (12) | 2FA token verification request succeeded.

## Authentication

### POST `/auth/login`

Authenticate an existing user, using an email address and password.

Does not reveal if the provided email address is in-use, by comparing a dummy hash to show no difference in response duration.

#### Request

##### Headers

Key | Value
--- | ---
`Content-Type` | `application/json`

##### Body

Key | Value
--- | ---
`email` | Email address of the user account.
`password` | Password of the user account.

#### Response

Status | Body | Description
--- | --- | ---
200 | `session`, `token` | Success
400 | Error | Email and/or password were not provided
401 | Error | Email and password combination is incorrect (also returned when the email is not in-use)
500 | Error | -

### POST `/auth/reset`

Request a password reset email by providing an email adress and callback link to include in the email.

Does not reveal if the provided email address is in-use, by generating a dummy JWT to show no difference in response duration.

#### Request

##### Headers

Key | Value
--- | ---
`Content-Type` | `application/json`

##### Body

Key | Value
--- | ---
`email` | Email address of the user account.
`link` | Link to paste the token to and include in the reset email.

Example:
```json
{
	"email": "j.smienk@mail.com",
	"link": "https://myapplication.com/reset?token="
}
```

#### Response

Status | Body | Description
--- | --- | ---
204 | - | Success (also returned if the email is not in-use).
400 | Error | Email or link is not provided.
500 | Error | -

### PUT `/auth/reset/:token`

Reset a password of an existing user account. Requires a special JWT (sent to the user's email address) and a new password in the body.

The user does not have to be verified to request a password reset.

#### Request

##### Headers

Key | Value
--- | ---
`Content-Type` | `application/json`

##### Query parameters

Key | Value
--- | ---
`token` | JWT that expires in a very short time and allows the reset of the user's account password. It includes the user's ID.

##### Body

Key | Value
--- | ---
`password` | New password to set to the user account.

#### Response

Status | Body | Description
--- | --- | ---
204 | - | Success
400 | Error | Token is not provided or password is not provided or not good enough.
404 | Error | ID in token does not belong to a user (anymore).
500 | Error | -

### PUT `/auth/verify/:token`

Verify the email address of an existing user account. Requires a special JWT that was sent to the user's provided email address.

#### Request

##### Query parameters

Key | Value
--- | ---
`token` | JWT that expires in a very short time and allows the verification of the user's account. It includes the user's ID.

#### Response

Status | Body | Description
--- | --- | ---
204 | - | Success
400 | Error | Token is not provided.
404 | Error | ID in token does not belong to a user (anymore).
500 | Error | -

### POST `/auth/2fa`

Prepare 2FA by requesting a QR string to allow the user to add this application to any 2FA mobile application.

#### Request

##### Headers

Key | Value
--- | ---
`Authorization` | JWT token

#### Response

Status | Body | Description
--- | --- | ---
201 | `registration` | QR string to allow the user to add this application to any 2FA mobile application.
401 | Error | No (valid) JWT in `Authorization` header.
404 | Error | Account with ID from JWT not found.
500 | Error | -

### POST `/auth/2fa/verify`

Verify a 2FA token.

When the user account has 2FA disabled, a successful request also returns 401 to hide this fact.

#### Request

##### Headers

Key | Value
--- | ---
`Authorization` | JWT token

##### Body

Key | Value
--- | ---
`token` | 6-digit TOTP token string generated by any mobile authenticator application.

#### Response

Status | Body | Description
--- | --- | ---
200 | `session`, `token` | 6-digit TOTP token was verified.
400 | Error | 6-digit TOTP token was not provided.
401 | Error | No (valid) JWT in `Authorization` header; 6-digit TOTP token could *not* be verified; User has 2FA disabled.
404 | Error | User to verify not found.
500 | Error | -

### DELETE `/auth/2fa`

Disable 2FA.

#### Request

##### Headers

Key | Value
--- | ---
`Authorization` | JWT token

#### Response

Status | Body | Description
--- | --- | ---
204 | - | Success.
401 | Error | No (valid) JWT in `Authorization` header.
404 | Error | Account with ID from JWT not found.
500 | Error | -

## Users collection

Retrieving, creating, editing, deleting user accounts.

### GET `/users`

Get information about all users.

#### Request

##### Headers

Key | Value
--- | ---
`Authorization` | JWT token

#### Response

Status | Body | Description
--- | --- | ---
200 | List of users | Success
401 | Error | No (valid) JWT in `Authorization` header.
404 | Error | No users.
500 | Error | -

### POST `/users`

Register a new user account by providing an email address, display name and password.

Email addresses are matched with a regular expression that can be set in `config.js`.

Names are matched with a regular expression that can be set in `config.js`.

Passwords should be of sufficient length, which can also be set in `config.js`.

User account email address is **not verified** by default.

#### Request

##### Headers

Key | Value
--- | ---
`Content-Type` | `application/json`

##### Body

Key | Value
--- | ---
`email` | Email address to use.
`name` | Display name to use.
`password` | Password to use.
`link` | Callback link to paste the token to and include in the verification email.

Example:
```json
{
	"email": "j.smienk@mail.com",
	"name": "Jeroen Smienk",
	"password": "S3cur3P4ssw0rd",
	"link": "https://myapplication.com/verify?token="
}
```

#### Response

Status | Body | Description
--- | --- | ---
201 | Success message | User account is created.
400 | Error | Link, email address, name, or password is not provided or the email address, name or password is invalid.
409 | Error | Email address is already in-use.
500 | Error | -

### GET `/users/:id`

Get information about a specific user using its account id.

#### Request

##### Headers

Key | Value
--- | ---
`Authorization` | JWT token

##### Query parameters

Key | Value
--- | ---
`id` | ID of the user account to retrieve.

#### Response

Status | Body | Description
--- | --- | ---
200 | User object | Success
400 | Error | ID was not provided or invalid format.
401 | Error | No (valid) JWT in `Authorization` header.
404 | Error | ID does not belong to a user.
500 | Error | -

### PUT `/users/:id`

Change information about a specific user.

Only changes the fields that are provided.

If the email address is changed, the account is set back to **not verified**.

#### Request

##### Headers

Key | Value
--- | ---
`Authorization` | JWT token
`Content-Type` | `application/json`

##### Query parameters

Key | Value
--- | ---
`id` | ID of the user account to change.

#### Body

Key | Value
--- | ---
`email` | (OPTIONAL) Email address to change to.
`name` | (OPTIONAL) Display name to change to.
`password` | (OPTIONAL) Password to change to.

#### Response

Status | Body | Description
--- | --- | ---
204 | - | Account details were successfully updated.
400 | Error | ID was not provided or invalid format; Neither an email, name, or password was provided; Password is of insufficient length.
401 | Error | No (valid) JWT in `Authorization` header.
403 | Error | Authenticated user is not authorized to update the specified user.
404 | Error | Provided ID does not belong to a user.
409 | Error | New email address (if provided) is already in-use.
500 | Error | -

### DELETE `/users/:id`

Delete a specific user account.

#### Request

##### Headers

Key | Value
--- | ---
`Authorization` | JWT token

##### Query parameters

Key | Value
--- | ---
`id` | ID of the user account to delete.

#### Response

Status | Body | Description
--- | --- | ---
204 | - | Account was successfully deleted.
400 | Error | ID was not provided or invalid format.
401 | Error | No (valid) JWT in `Authorization` header.
403 | Error | Authenticated user is not authorized to delete the specified user.
404 | Error | Provided ID does not belong to a user.
500 | Error | -
