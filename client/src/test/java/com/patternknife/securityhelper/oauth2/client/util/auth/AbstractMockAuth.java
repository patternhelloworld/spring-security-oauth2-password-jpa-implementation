package com.patternknife.securityhelper.oauth2.client.util.auth;

import com.patternknife.securityhelper.oauth2.client.config.securityimpl.guard.AccessTokenUserInfo;
import com.patternknife.securityhelper.oauth2.client.config.securityimpl.guard.AdditionalAccessTokenUserInfo;
import com.patternknife.securityhelper.oauth2.client.domain.customer.entity.Customer;
import com.patternknife.securityhelper.oauth2.client.domain.customer.entity.Password;
import org.junit.jupiter.api.Assertions;
import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public abstract class AbstractMockAuth implements MockAuth {

    public static final Long MOCKED_CUSTOMER_ACCESS_TOKEN_ORGANIZATION_ID = 5L;
    public static final Long MOCKED_CUSTOMER_ACCESS_TOKEN_CUSTOMER_ID = 1L;

    @Override
    public AccessTokenUserInfo mockAuthenticationPrincipal(Customer customer) {

        String username= customer.getEmail();
        String password = customer.getPassword().getValue();

        boolean enabled = true;
        boolean accountNonExpired = true;
        boolean credentialsNonExpired = true;
        boolean accountNonLocked = true;

        AccessTokenUserInfo authCustomer = new AccessTokenUserInfo(username, password, enabled, accountNonExpired, credentialsNonExpired,
                accountNonLocked, getAuthorities(customer));

        authCustomer.setAdditionalAccessTokenUserInfo(new AdditionalAccessTokenUserInfo(customer));

        return authCustomer;
    }
    private static Collection<? extends GrantedAuthority> getAuthorities(Customer customer) {
        if(customer.getCustomerRoles() == null){
            return new ArrayList<>();
        }

        String[] customerRoles = customer.getCustomerRoles().stream().map((customerRole) -> customerRole.getRole().getName()).toArray(String[]::new);
        Collection<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(customerRoles);
        return authorities;
    }

    @Override
    public Customer mockCustomerObject() {


        Customer customer = Customer.builder()
                        .id(MOCKED_CUSTOMER_ACCESS_TOKEN_CUSTOMER_ID).email("cicd@test.com")
                        .name("tester").password(new Password("1113333ddd1"))
                        .build();

        return customer;
    }


    protected TestRestTemplate testRestTemplate;
    protected MockMvc mockMvc;

    @Override
    public String mockAccessToken(String clientName, String clientPassword, String username, String password) throws Exception {

        if(this.mockMvc == null){
            throw new Exception("mockMvc must be initially injected.");
        }

        MultiValueMap<String, String> request = new LinkedMultiValueMap<>();
        request.set("username", username);
        request.set("password", password);
        request.set("grant_type", "password");

        ResultActions result
                = this.mockMvc.perform(post("/api/v1/traditional-oauth/token")
                .params(request)
                .with(httpBasic(clientName,clientPassword))
                .accept("application/json;charset=UTF-8"))
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/json;charset=UTF-8"));

        String resultString = result.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

        JacksonJsonParser jsonParser = new JacksonJsonParser();
        return jsonParser.parseMap(resultString).get("access_token").toString();
    }

    @Override
    public String mockAccessTokenOnPersistence(String authUrl, String clientName, String clientPassword, String username, String password) throws Exception {
        if(authUrl == null){
            throw new Exception("authUrl must be indicated for the integration test");
        }

        if(this.testRestTemplate == null){
            throw new Exception("testRestTemplate must be injected in the access-tokenstore-way integration test");
        }

        MultiValueMap<String, String> request = new LinkedMultiValueMap<>();
        request.set("username", username);
        request.set("password", password);
        request.set("grant_type", "password");

        @SuppressWarnings("unchecked")
        Map<String, Object> token = this.testRestTemplate.withBasicAuth(clientName, clientPassword)
                .postForObject(authUrl + "/api/v1/traditional-oauth/token", request, Map.class);

        Assertions.assertNotNull(token.get("access_token"),"Wrong credentials with DB : " + token);

        return (String) token.get("access_token");
    }
}
