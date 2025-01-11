# Spring Oauth2 EasyPlus

> App-Token based easy OAuth2 implementation built to grow with Spring Boot

## Table of Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Dependencies](#dependencies)
- [Run the App](#run-the-app)
- [API Guide](#api-guide)
    - [Registration](#registration)
    - [Implementations](#implementations)
        - [Mandatory Settings](#mandatory-settings)
        - [Customizable Settings](#customizable-settings)
- [OAuth2 - ROPC](#oauth2---ropc)
- [OAuth2 - Authorization Code](#oauth2---authorization-code)
- [Running this App with Docker](#running-this-app-with-docker)
- [Contribution Guide](#contribution-guide)


## Quick Start
```xml
<dependency>
    <groupId>io.github.patternhelloworld.securityhelper.oauth2.api</groupId>
    <artifactId>spring-oauth2-easyplus</artifactId>
    <version>4.0.1</version>
</dependency>
```


## Features

* Complete separation of the library and the client
    * Library : API
    * Client : DOC, Integration tester
* Use JPA for various databases to gain full control over all tokens and permissions, unlike simple in-memory examples.
* Extensible: Supports multiple authorization servers and resource servers with this library.
* Hybrid Resource Servers Token Verification Methods: Support for multiple verification approaches, including API calls to the authorization server, direct database validation, and local JWT decoding.
* Immediate Permission (Authority) Check: Not limited to verifying the token itself, but also ensuring real-time validation of any updates to permissions in the database.
* Authentication management based on a combination of username, client ID, and App-Token
    * What is an App-Token? An App-Token is a new access token generated each time the same account logs in. If the token values are the same, the same access token is shared.

| App-Token Status       | Access Token Behavior      |
|------------------------|----------------------------|
| same for the same user | Access-Token is shared     |
| different for the same user | Access-Token is NOT shared |

* Set this in your ``application.properties``.
    * App-Token Behavior Based on `io.github.patternhelloworld.securityhelper.oauth2.no-app-token-same-access-token`

| `no-app-token-same-access-token` Value | App-Token Status                          | Access Token Sharing Behavior                                                                                     |
|------------------------------------------------------------|-------------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| `true`                                                     | App-Token is `null` for the same user     | Same user with a `null` App-Token shares the same access token across multiple logins.                             |
| `false`                                                    | App-Token is `null` for the same user                       | Even if the App-Token is `null`, the same user will receive a new access token for each login.                     |
| `-`                                                        | App-Token is shared for the same user     | Access tokens will not be shared. A new access token is generated for each unique App-Token, even for the same user.|
| `-`                                                        | App-Token is NOT shared for the same user | Each unique App-Token generates a new access token for the same user.                                              |


* Separated UserDetails implementation for Admin and Customer roles as an example. (This can be extended such as Admin, Customer, Seller and Buyer... by implementing ``UserDetailsServiceFactory``)
* Set up the same access & refresh token APIs on both ``/oauth2/token`` and on our controller layer such as ``/api/v1/traditional-oauth/token``, both of which function same and have `the same request & response payloads for success and errors`. (However, ``/oauth2/token`` is the standard that "spring-authorization-server" provides.)
    * As you are aware, the API ``/oauth2/token`` is what "spring-authorization-server" provides.
        * ``/api/v1/traditional-oauth/token`` is what this library implemented directly.
            * Success Payload
             ```json
              {
                  "access_token" : "Vd4x8D4lDg7VBFh...",
                  "token_type" : "Bearer",
                  "refresh_token" : "m3UgLrvPtXKdy7jiD...",
                  "expires_in" : 3469,
                  "scope" : "read write"
               }
            ```

            * Error Payload (Customizable)
            ```json
              {
                  "timestamp": 1719470948370,
                  "message": "Couldn't find the client ID : client_admin", // Sensitive info such as being thrown from StackTraces
                  "details": "uri=/oauth2/token",
                  "userMessage": "Authentication failed. Please check your credentials.",
                  "userValidationMessage": null
              }
            ```

            * In the following error payload, the 'message' shouldn't be exposed to clients; instead, the 'userMessage' should be.

* Application of Spring Rest Docs, Postman payloads provided

## Dependencies

| Category          | Dependencies                                                           |
|-------------------|------------------------------------------------------------------------|
| Backend-Language  | Java 17                                                                |
| Backend-Framework | Spring Boot 3.3.2 (the latest version)                                 |
| Main Libraries    | Spring Security 6.3.1, Spring Security Authorization Server 1.3.1, JPA |
| Package-Manager   | Maven 3.6.3 (mvnw, Dockerfile)                                         |
| RDBMS             | Mysql 8.0.17                                                           |

## Run the App

#### Import the SQL file in the ``mysql`` folder.
- If you don't have a MySQL instance readily available, you can clone https://github.com/patternhelloworld/docker-mysql-8 .

#### Install Maven
```shell
# Do NOT use your latest Maven version, but mvnw here or one with the same version.
cd lib
mvnw clean install
cd ..
cd client
mvnw clean install # Integration tests are done here, which creates docs by Spring-Rest-Doc.
```
- Run the client module by running ``SpringSecurityOauth2PasswordJpaImplApplication`` in the client.
- The API information is found on ``http://localhost:8370/docs/api-app.html``, managed by Spring Rest Doc

![img.png](reference/docs/img1.png)

- In case you use IntelliJ, I recommend creating an empty project and importing the API (root) module and client module separately.
- The client module definitely consumes the API module, but not vice versa.

## API Guide

### **Registration**
- See the `client` folder.
- As the Api module consumes JPA, adding it to Beans is required.

```java

// Add 'io.github.patternhelloworld.securityhelper.oauth2.api'
@SpringBootApplication(scanBasePackages =  {"com.patternhelloworld.securityhelper.oauth2.client", "io.github.patternhelloworld.securityhelper.oauth2.api"})
public class SpringSecurityOauth2PasswordJpaImplApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityOauth2PasswordJpaImplApplication.class, args);
    }

}
```

```java
@Configuration
// ADD 'io.github.patternhelloworld.securityhelper.oauth2.api.config.security'
@EnableJpaRepositories(
        basePackages = {"com.patternhelloworld.securityhelper.oauth2.client.domain",
                "com.patternhelloworld.securityhelper.oauth2.client.config.securityimpl",
                "io.github.patternhelloworld.securityhelper.oauth2.api.config.security"},
        entityManagerFactoryRef = "commonEntityManagerFactory",
        transactionManagerRef= "commonTransactionManager"
)
public class CommonDataSourceConfiguration {
    

   // ADD 'io.github.patternhelloworld.securityhelper.oauth2.api.config.security'
    @Primary
    @Bean(name = "commonEntityManagerFactory")
    public LocalContainerEntityManagerFactoryBean commonEntityManagerFactory(EntityManagerFactoryBuilder builder) {
        return builder
                .dataSource(commonDataSource())
                .packages("com.patternhelloworld.securityhelper.oauth2.client.domain",
                        "io.github.patternhelloworld.securityhelper.oauth2.api.config.security")
                .persistenceUnit("commonEntityManager")
                .build();
    }

}
```

### **Implementations**
- As indicated, the ``client`` folder demonstrates how to use this library.

#### "Mandatory" settings

- The only mandatory setting is ``client.config.securityimpl.service.userdetail.CustomUserDetailsServiceFactory``. The rest depend on your specific situation.

#### "Customizable" settings

- **Insert your code when events happen such as tokens created**
    - ``SecurityPointCut``
    - See the source code in ``client.config.securityimpl.aop``


- **Register error user messages as desired**
    - ``ISecurityUserExceptionMessageService``
    - See the source code in ``client.config.securityimpl.message``


- **Customize the whole error payload as desired for all cases**
    - What is "all cases"?
        - Authorization Server ("/oauth2/token", "/api/v1/traditional-oauth/token") and Resource Server (Bearer token authentication : 401, authorization (permission) : 403)
    - Customize errors of the following cases
        - Login (/oauth2/token) : ``client.config.securityimpl.response.CustomAuthenticationFailureHandlerImpl``
        - Login (/api/v1/traditional-oauth/token) : ``client.config.response.error.GlobalExceptionHandler.authenticationException`` ("/api/v1/traditional-oauth/token", Resource Server (Bearer token inspection))
        - Resource Server (Bearer token expired or with a wrong value, 401) :``client.config.securityimpl.response.CustomAuthenticationEntryPointImpl``
        - Resource Server (Permission, 403, @PreAuthorized on your APIs) ``client.config.response.error.GlobalExceptionHandler.authorizationException``

- **Customize the whole success payload as desired for the only "/oauth2/token"**
    - ``client.config.securityimpl.response.CustomAuthenticationSuccessHandlerImpl``
    - The success response payload of "/api/v1/traditional-oauth/token" is in ``api.domain.traditionaloauth.dto`` and is not yet customizable.

- **Customize the verification logic for UsernamePassword and Client as desired**
    - ``IOauth2AuthenticationHashCheckService``

- **Customize OpaqueTokenIntrospector as desired (!This is for Resource Servers)**
    - ``client.config.securityimpl.introspector.CustomResourceServerTokenIntrospector``
    - ```properties
          # Introspection type configuration:
          # - api: The Resource Server sends introspection requests to the Authorization Server.
          #        Benefits: High scalability and real-time authorization checks.
          #        Drawbacks: Increased traffic due to frequent API calls.
          # 
          # - database: The Resource Server and Authorization Server share the same database.
          #             Benefits: Minimal traffic and real-time authorization checks.
          #             Drawbacks: Limited scalability due to direct database dependency.
          # 
          # - decode: The Resource Server decodes the Access Token locally using the JWT algorithm.
          #           Benefits: No traffic and high scalability.
          #           Drawbacks: Lacks real-time authorization updates.
          #
          # [WARNING] api: Certain test cases are currently failing due to issues with the specified introspection URI calls.
          patternhelloworld.securityhelper.oauth2.introspection.type=database
          patternhelloworld.securityhelper.oauth2.introspection.uri=http://localhost:8370/oauth2/introspect
          patternhelloworld.securityhelper.oauth2.introspection.client-id=client_customer
          patternhelloworld.securityhelper.oauth2.introspection.client-secret=12345
        ```
## OAuth2 - ROPC
* Refer to ``client/src/docs/asciidoc/api-app.adoc``

## OAuth2 - Authorization Code
- Beta
- How to set it up
    1. Create your own login page with the /login route as indicated in the client project (In the future, this address will be customisable):
  ```java
    @Controller
    public class LoginWeb {
        @GetMapping("/login")
        public String loginPage() {
        return "login";
        }
    }
  ```
  ```properties
    spring.mvc.view.prefix=/templates/
    spring.mvc.view.suffix=.html
  ```
    2. Check the login page at the "resources/templates/login.hml"
    3. Ensure the callback URL (http://localhost:8081/callback1) is properly set in the ``oauth2_registered_client`` table in the database.
- How to use
    1. Open the web browser by connecting to ``http://localhost:8370/oauth2/authorize?response_type=code&client_id=client_customer&state=xxx&scope=read&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fcallback1``, using the values from the ``oauth2_registered_client``  2. Now you Login with ``cicd@test.com / 1234 ``
    2. Login with ``cicd@test.com / 1234 ``
    3. You will be redirected to
       ``https://localhost:8081/callback1?code=215e9539-1dcb-4843-b1ea-b2d7be0a3c44&state=xxx``
    4. You can login with this API payload
    ```http request
    POST /oauth2/token HTTP/1.1
    Host: localhost:8370
    Accept: application/json
    Content-Type: application/x-www-form-urlencoded
    App-Token: aaa # You can achieve the separated and shared session using App-Token
    Authorization: ••••••
    Content-Length: 57
    grant_type=code&code=ef5aaaaf-ebae-4677-aac5-abf8e8412f1e
    ```

## Running this App with Docker
* Use the following module for Blue-Green deployment:
    * https://github.com/patternhelloworld/docker-blue-green-runner
* The above module references this app's Dockerfile and the entrypoint script in the .docker folder.

## Contribution Guide
* You can create a pull request directly to the main branch.
* Integration tests in the client folder are sufficient for now, but you may add more if necessary.
* There is a lack of unit tests, so contributions to unit test code are welcome, which will help improve the overall codebase.