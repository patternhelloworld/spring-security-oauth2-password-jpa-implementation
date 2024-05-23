# POC : Spring Security Oauth2 Password JPA Implementation
## Overview

* In the Spring Security 6 ecosystem, compared to 5, there is a preference for JWT or Keycloak over traditional OAuth2 using a Password Grant method with Spring Security Authorization and Resource Server. I needed to incorporate the current OAuth2 Password Grant with the Spring Security new version and am showing the customization.
  * Set up access & refresh token APIs on both '/oauth2/token' and on our controller layer such as '/api/v1...', both of which function same.
  * Authentication management based on a combination of username, client id, and an extra token (referred to in the source code as App-Token, which receives a unique value from the calling devices).
  * Separated UserDetails implementation for Admin and Customer roles.
  * Integration with spring-security-oauth2-authorization-server.
    * Provide MySQL DDL, which consists of oauth\_access\_token, oauth\_refresh\_token and oauth\_client\_details, which is tables in Security 5. As I mean to migrate current security system to Security 6, I haven't changed them to the ``authorization`` table indicated in https://github.com/spring-projects/spring-authorization-server.
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

#### The API information is found on ``http://localhost:8505/docs/api-app.html``, managed by Spring Rest Doc 



### Running this App with Docker
* Use the following module for Blue-Green deployment:
  * https://github.com/Andrew-Kang-G/docker-blue-green-runner
* The above module references this app's Dockerfile and the entrypoint script in the .docker folder.