# Agave Java Client Auth Library

This is a light client library for authenticating to the Agave Platform. It builds on the [scribejava](https://github.com/scribejava/scribejava) and [nimbus-jose](https://connect2id.com/products/nimbus-jose-jwt) libraries to provide utility classes for authenticating and managing credentials across one or more tenants.  

## Features

* convenience classes for parsing and validating JWT sent from the Agave API Manager.
* Fetch and automatically refreshing tokens.
* Provides configurable caching through ehcache. (Memory caching by default).
* Supports token invalidation.
* Full support for Agave's custom `admin_password` grant type allowing the creation and management of impersonation tokens by any user with the `impersonation` role.  

## Building  

Standard maven build applies.

```
mvn clean install
```  

## Including  

Include in your project with the following dependency

```  
<dependency>
	<groupId>org.agave.client</groupId>
	<artifactId>client-auth</artifactId>
	<version>0.1.0-SNAPSHOT</version>
</dependency>  
```  

## Configuring

The `client-auth` library uses the [Agave Java SDK](https://github.com/deardooley/agave-java-sdk) to communicate with various platform services. You need to tell the library which tenant to use and provide it with a valid set of client keys and auth info if you intend on using the implicity grant type. The library will look for an auth cache file, identical to that produced by the Agave CLI and Python SDK, in the following locations listed in order in which they are checked:  

* `/run/secrets/SERVICE_ACCOUNT_AUTH_CACHE_FILE`.  
* `$AGAVE_CACHE_DIR/current`  
* `$HOME/.agave/current`  

You can also override any of the values in that file using environment variables present when your application starts. The following environment variables are supported.  

| Name                          | Type   | Description                                                                                                                                                 |   |
|-------------------------------|--------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|---|
| API_BASE_URL                  | string | The base URL to use in all API requests                                                                                                                     |   |
| API_VERSION                   | string | The API version to use. Default value is "v2"                                                                                                               |   |
| SERVICE_ACCOUNT_TENANT_ID     | string | The id of your tenant. This is the `code` value in the response from the tenants api. Default value is "agave.prod"                                         |   |
| SERVICE_ACCOUNT_USERNAME      | string | Username of the service account used for interacting with the API. This will be your "application user"                                                     |   |
| SERVICE_ACCOUNT_PASSWORD      | string | Password of the service account used for interacting with the API. This will be your "application user"                                                     |   |
| SERVICE_ACCOUNT_CLIENT_KEY    | string | Client API key of the service account used for interacting with the API. This should be a dedicated client you create specifically for your application.    |   |
| SERVICE_ACCOUNT_CLIENT_SECRET | string | Client API secret of the service account used for interacting with the API. This should be a dedicated client you create specifically for your application. |   |
| SERVICE_ACCOUNT_ACCESS_TOKEN  | string | A valid access token for use by your application. This is not                                                                                               |   |
| SERVICE_ACCOUNT_REFRESH_TOKEN | string | A valid refresh token for use by your application to automatically refresh the auth token.                                                                  |   |   

