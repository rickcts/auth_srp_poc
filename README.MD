# SCS AAA Server API
API for Authentication, Authorization, and Accounting services.

## Version: v1

### /api/auth/sessions/list

#### GET
##### Summary:

Get active sessions for the current user

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | Successfully retrieved sessions. |
| 401 | Unauthorized. Invalid or missing JWT. |
| 500 | Internal Server Error. |

##### Security

| Security Schema | Scopes |
| --- | --- |
| JWTAuth | |

### /api/auth/sessions/verify

#### POST
##### Summary:

Verify the current JWT session token

##### Responses

| Code | Description |
| ---- | ----------- |
| 204 | Token is valid. |
| 401 | Unauthorized. Invalid, expired, or missing JWT. |

##### Security

| Security Schema | Scopes |
| --- | --- |
| JWTAuth | |

### /api/auth/sessions/logout

#### POST
##### Summary:

Logout the current session

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | Successfully logged out. |
| 401 | Unauthorized. Invalid or missing JWT. |
| 500 | Internal Server Error. |

##### Security

| Security Schema | Scopes |
| --- | --- |
| JWTAuth | |

### /api/auth/sessions/logout-all

#### POST
##### Summary:

Logout all sessions for the current user, optionally excluding the current one

##### Description:

The current session token (from Authorization header) will be excluded from logout if provided and valid.

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | Successfully logged out other devices. |
| 401 | Unauthorized. Invalid or missing JWT. |
| 500 | Internal Server Error. |

##### Security

| Security Schema | Scopes |
| --- | --- |
| JWTAuth | |

### /api/auth/users/

#### PUT
##### Summary:

Update current user's information

##### Responses

| Code | Description |
| ---- | ----------- |
| 205 | User information updated successfully. |
| 400 | Bad Request. Invalid request body. |
| 401 | Unauthorized. Invalid or missing JWT. |
| 500 | Internal Server Error. |

##### Security

| Security Schema | Scopes |
| --- | --- |
| JWTAuth | |

#### DELETE
##### Summary:

Delete the current user's account

##### Responses

| Code | Description |
| ---- | ----------- |
| 204 | User account deleted successfully. |
| 401 | Unauthorized. Invalid or missing JWT. |
| 500 | Internal Server Error. |

##### Security

| Security Schema | Scopes |
| --- | --- |
| JWTAuth | |

### /api/auth/srp/sign-up/check

#### POST
##### Summary:

Check if an email (AuthID) already exists

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | Check result. |
| 400 | Bad Request. AuthID is required. |
| 409 | Conflict. This email is already in use. |
| 500 | Internal Server Error. |

### /api/auth/srp/sign-up

#### POST
##### Summary:

Register a new user with SRP credentials

##### Responses

| Code | Description |
| ---- | ----------- |
| 201 | User registered successfully (account may be inactive). |
| 400 | Bad Request. Invalid request body. |
| 409 | Conflict. Username already exists. |
| 500 | Internal Server Error. Registration failed. |

### /api/auth/srp/sign-up/verification

#### POST
##### Summary:

Generate and send an activation email to the user

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | Activation email sent successfully. |
| 400 | Bad Request. AuthID is required. |
| 404 | Not Found. User not found. |
| 409 | Conflict. User is already activated. |
| 429 | Too Many Requests. The user has requested an activation email too recently. |
| 500 | Internal Server Error. Failed to send activation email. |

### /api/auth/srp/sign-up/activate

#### POST
##### Summary:

Activate a user account with an activation code

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | User activated successfully. |
| 400 | Bad Request. Invalid request body. |
| 401 | Unauthorized. Invalid, expired, or already consumed activation code. |
| 404 | Not Found. User not found. |
| 500 | Internal Server Error. Failed to activate user. |

### /api/auth/srp/login/email

#### POST
##### Summary:

SRP Step 1 - Client sends AuthID (email)

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | Server responds with salt (s) and server public ephemeral (B). |
| 400 | Bad Request. Invalid request body. |
| 401 | Unauthorized. Invalid client credentials (user not found). |
| 403 | Forbidden. User has not been activated. |
| 500 | Internal Server Error. Authentication initiation failed. |

### /api/auth/srp/login/proof

#### POST
##### Summary:

SRP Step 2 - Client sends proof (A, M1)

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | Authentication successful. Server responds with its proof (M2) and session token. |
| 400 | Bad Request. Invalid request body. |
| 401 | Unauthorized. Authentication session expired or invalid credentials/proof. |
| 500 | Internal Server Error. Authentication verification failed. |

### /api/auth/srp/password/reset

#### POST
##### Summary:

Initiate password reset process (Email will only be sent once every minute, or will be rate limited)

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | If the account exists, a password reset email has been sent. |
| 400 | Bad Request. Invalid request body. |
| 429 | Too Many Requests. The user has requested a password reset too recently. |
| 500 | Internal Server Error. Password reset initiation failed. |

### /api/auth/srp/password/reset/validate

#### POST
##### Summary:

Validate a password reset token

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | Token validation result. |
| 400 | Bad Request. Token or AuthID cannot be empty. |
| 401 | Unauthorized. Token is invalid or expired. |

### /api/auth/srp/password/reset/complete

#### POST
##### Summary:

Complete the password reset process with a new password

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | Password has been reset successfully. |
| 400 | Bad Request. Invalid request body or token. |

### /api/auth/srp/password/change/initiate

#### POST
##### Summary:

Initiate password change for an authenticated user (Step 1)

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | Server responds with current salt and server public ephemeral 'B'. |
| 401 | Unauthorized. Invalid or missing JWT. |
| 500 | Internal Server Error. |

##### Security

| Security Schema | Scopes |
| --- | --- |
| JWTAuth | |

### /api/auth/srp/password/change/confirm

#### POST
##### Summary:

Confirm password change for an authenticated user (Step 2)

##### Responses

| Code | Description |
| ---- | ----------- |
| 204 | Password changed successfully. |
| 400 | Bad Request. Invalid request body. |
| 401 | Unauthorized. Current password verification failed or session expired. |
| 500 | Internal Server Error. |

##### Security

| Security Schema | Scopes |
| --- | --- |
| JWTAuth | |

### /api/auth/oauth/microsoft/login

#### GET
##### Summary:

Initiate OAuth2 login flow with Microsoft

##### Description:

Redirects the user to Microsoft's login page. Sets a state cookie for CSRF protection.

##### Responses

| Code | Description |
| ---- | ----------- |
| 307 | Temporary Redirect to Microsoft's authorization server. The 'Location' header contains the redirect URL. A state cookie is set. |

### /api/auth/oauth/microsoft/callback

#### GET
##### Summary:

OAuth2 callback endpoint for Microsoft

##### Description:

Handles the redirect from Microsoft after user authentication. Exchanges authorization code for tokens and fetches user info. Clears the state cookie.

##### Parameters

| Name | Located in | Description | Required | Schema |
| ---- | ---------- | ----------- | -------- | ---- |
| code | query | The authorization code from Microsoft. | No | string |
| state | query | The state parameter for CSRF protection. Must match the value in the state cookie. | Yes | string |
| error | query | Error code from Microsoft if authentication failed. | No | string |
| error_description | query | Description of the error from Microsoft. | No | string |

##### Responses

| Code | Description |
| ---- | ----------- |
| 200 | Login successful. |
| 400 | Bad Request. State mismatch, missing code, or other OAuth error. |
| 401 | Unauthorized. Invalid state parameter. |
| 500 | Internal Server Error. Failed to exchange code or fetch user info. |

### /api/auth/oauth/microsoft/mobile

#### POST
##### Summary:

Handle OAuth2 token exchange for mobile applications (PKCE)

##### Description:

Exchanges an authorization code and PKCE verifier for tokens.

##### Responses

| Code | Description |
| ---- | ----------- |
| 201 | Login successful. |
| 400 | Bad Request. Missing code or code_verifier, or invalid request body. |
| 500 | Internal Server Error. Failed to authenticate with provider or fetch user info. |
