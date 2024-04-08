# Spring Security Oauth2 Password JPA Implementation
## Overview

* In the Spring Security 6 ecosystem, compared to 5, there is a preference for Jwt or Keycloak over traditional OAuth2, and for the Authorization Code flow over the Password Grant method. In this context, the OAuth2 Password Grant method has been implemented with the following advantages:

  * Set up access & refresh token API on both ``/oauth2/token`` and on the controller layer, both of which function same. 
  * Authentication management based on a combination of username, client id, and an extra token (referred to in the source code as ``App-Token``, which receives a unique value from the calling devices).
  * Separated UserDetails implementation for Admin and Customer roles.
  * Integration with spring-security-oauth2-authorization-server.
    * Provision of MySQL DDL, which consists of ``oauth_access_token``, ``oauth_refresh_token`` and ``oauth_client_details``
  * Application of Spring Rest Docs.

## Dependencies

| Category          | Dependencies                               |
|-------------------|--------------------------------------------|
| Backend-Language  | Java 17                                    |
| Backend-Framework | Spring Boot 3.1.2                          |
| Main Libraries    | Spring Security Authorization Server 1.2.3 |
| Package-Manager   | Maven 3.6.3 (mvnw, Dockerfile)             |
| RDBMS             | Mysql 8.0.17                               |

## Implementation

#### Import the SQL file in the ``mysql`` folder.

#### The API information is on ``src/main/asciidoc/api-app.adoc``, managed by Spring Rest Doc.



### Running this App with Docker
* Use the following module for Blue-Green deployment:
  * https://github.com/Andrew-Kang-G/docker-blue-green-runner
* The above module references this app's Dockerfile and the entrypoint script in the .docker folder.