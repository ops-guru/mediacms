# MediaCMS Customizations

This document describes the customizations made to the MediaCMS installation and explains the reasoning behind each modification.

## Deployment Customizations

### docker-compose-letsencrypt.yaml

**Changes:**
- Copied to the root MediaCMS folder
- Updated the image from `mediacms/mediacms:latest` to `mediacms/mediacms:5.0.1`

**Reasoning:**
- **Version synchronization**: The server has a mount point used by docker images that contains all the content for a specific version. The container running and the content in the file mount must match exactly.
- **Preventing version mismatch**: Using `latest` could result in the container running a different version than what exists in the mount directory, causing content conflicts or missing files.
- **Deployment stability**: Using a specific pinned version (`5.0.1`) ensures that the code in the container aligns with the mounted content, preventing runtime errors.
- **Controlled updates**: When upgrading versions, both the container image and the mounted content can be updated together in a coordinated manner.

### Dockerfile.custom

**Changes:**
- Created to support Google Auth integration

**Reasoning:**
- **Google authentication**: Provides additional authentication option to support Google Authentication
- **Missing libraries**: The standard Dockerfile does not include some required libraries to use Google Auth

## Feature Customizations

### templates/config/installation/features.html

**Changes:**
- Download videos functionality disabled

**Reasoning:**
- **Copyright protection**: Prevents unauthorized downloading and distribution of video content

## SAML Authentication Customizations

### cms/urls.py

**Changes:**
- Intercepting standard SAML URLs (`/accounts/saml/<organization_slug>/login/`)
- Directing them to custom handler instead of default implementation

**Reasoning:**
- **Transparent integration**: Maintains compatibility with standard Okta configuration without requiring changes on the IdP side
- **Centralized control**: Allows for custom processing without modifying core library components

### saml_auth/adapter.py

**Changes:**
- Adding list-type attribute conversion
- Forcing authentication to bypass validation issues
- Adding anti-loop protection for login attempts

**Reasoning:**
- **List attribute handling**: Okta sometimes sends user attributes (email, name) as lists rather than strings, causing processing errors in the standard implementation
- **Validation flexibility**: Standard SAML validation can be overly strict, causing rejections of valid authentication attempts
- **Authentication loop prevention**: Detects and breaks potential redirect loops that can occur with SAML authentication

### saml_auth/custom/provider.py

**Changes:**
- Handling key identity attributes that come as lists
- Processing and storing these values consistently

**Reasoning:**
- **Attribute consistency**: Ensures that regardless of how attributes are sent (string or list), they are processed uniformly
- **Data integrity**: Prevents duplicate or malformed user records due to inconsistent attribute handling

### saml_auth/saml_auth_handler.py

**Changes:**
- Custom SAML response handling
- Direct XML parsing when library validation fails
- Comprehensive user creation and attribute mapping

**Reasoning:**
- **Robust authentication**: Provides a more resilient authentication flow that handles edge cases
- **Fallback mechanism**: Uses direct XML parsing when the standard SAML library fails to validate responses
- **Complete user provisioning**: Ensures all user attributes (email, first name, last name) are properly extracted and stored
- **Debugging capabilities**: Includes optional debug output to help troubleshoot authentication issues