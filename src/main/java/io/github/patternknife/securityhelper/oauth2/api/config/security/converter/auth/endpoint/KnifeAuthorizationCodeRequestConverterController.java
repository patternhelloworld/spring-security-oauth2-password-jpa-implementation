package io.github.patternknife.securityhelper.oauth2.api.config.security.converter.auth.endpoint;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * @author Daniel Garnier-Moiroux
 */
@Controller
public class KnifeAuthorizationCodeRequestConverterController {

    private final Log logger = LogFactory.getLog(this.getClass());

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationConsentService authorizationConsentService;
    private final OAuth2AuthorizationServiceImpl oAuth2AuthorizationService;
    private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

    public KnifeAuthorizationCodeRequestConverterController(RegisteredClientRepository registeredClientRepository,
                                                            OAuth2AuthorizationConsentService authorizationConsentService,
                                                            OAuth2AuthorizationServiceImpl oAuth2AuthorizationService, ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService) {
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationConsentService = authorizationConsentService;
        this.oAuth2AuthorizationService = oAuth2AuthorizationService;
        this.iSecurityUserExceptionMessageService = iSecurityUserExceptionMessageService;
    }


    @PostMapping("/oauth2/authorization")
    public String authorize(Model model, @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
                            @RequestParam(OAuth2ParameterNames.REDIRECT_URI) String redirectUri,
                            @RequestParam(name = OAuth2ParameterNames.CODE) String authorizationCode) {
        // 예시: 클라이언트의 등록된 콜백 URL 가져오기
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        if (!registeredClient.getRedirectUris().contains(redirectUri)) {
            logger.error("message (Invalid redirect URI when consenting): "
                    + "authorizationCode=" + authorizationCode + ", "
                    + "clientId=" + clientId + ", "
                    + "redirectUri=" + redirectUri + ", "
                    + "registeredRedirectUris=" + registeredClient.getRedirectUris().toString());
            model.addAttribute("userMessage", iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_INVALID_REDIRECT_URI));
            return "error";
        }

        OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationService.findByToken(authorizationCode, new OAuth2TokenType("authorization_code"));
        if(oAuth2Authorization == null){
            return "login";
        }
        String principalName = oAuth2Authorization.getPrincipalName();

        return "redirect:" + redirectUri + "?code=" + authorizationCode;
    }


    /*
    *   code, response_type, client_id, redirect_url
    * */
    @GetMapping(value = "/oauth2/authorization")
    public String consent(Model model,
                          @RequestParam(name = OAuth2ParameterNames.CODE) String authorizationCode,
                          @RequestParam(name = OAuth2ParameterNames.RESPONSE_TYPE) String responseType,
                          @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
                          @RequestParam(OAuth2ParameterNames.REDIRECT_URI) String redirectUri,
                          @RequestParam(name = OAuth2ParameterNames.SCOPE, required = false) String scope) {


        if(authorizationCode == null){
            return "login";
        }

        if (!"code".equals(responseType)) {
            logger.error("message (Invalid Authorization Code): "
                    + "authorizationCode=" + authorizationCode + ", "
                    + "responseType=" + responseType + ", "
                    + "clientId=" + clientId + ", "
                    + "redirectUri=" + redirectUri + ", "
                    + "scope=" + scope);
            model.addAttribute("userMessage", iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_INVALID_RESPONSE_TYPE));
            return "error";
        }

        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        if(registeredClient == null){
            logger.error("message (Invalid Client ID): "
                    + "authorizationCode=" + authorizationCode + ", "
                    + "responseType=" + responseType + ", "
                    + "clientId=" + clientId + ", "
                    + "redirectUri=" + redirectUri + ", "
                    + "scope=" + scope + ", ");
            model.addAttribute("userMessage", iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_WRONG_CLIENT_ID_SECRET));
            return "error";
        }

        if (!registeredClient.getRedirectUris().contains(redirectUri)) {
            logger.error("message (Invalid redirect URI): "
                    + "authorizationCode=" + authorizationCode + ", "
                    + "responseType=" + responseType + ", "
                    + "clientId=" + clientId + ", "
                    + "redirectUri=" + redirectUri + ", "
                    + "scope=" + scope + ", "
                    + "registeredRedirectUris=" + registeredClient.getRedirectUris().toString());
            model.addAttribute("userMessage", iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_INVALID_REDIRECT_URI));
            return "error";
        }



        OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationService.findByToken(authorizationCode, new OAuth2TokenType("authorization_code"));
        if(oAuth2Authorization == null){
            return "login";
        }
        String principalName = oAuth2Authorization.getPrincipalName();


        Set<String> approvedScopes = new HashSet<>();

        OAuth2AuthorizationConsent currentAuthorizationConsent =
                this.authorizationConsentService.findById(registeredClient.getId(), principalName);
        if(currentAuthorizationConsent != null){
            return "redirect:" + redirectUri + "?code=" + authorizationCode;
        }else{

            Set<String> authorizedScopes = registeredClient.getScopes();

            Set<String> requestedScopes = StringUtils.commaDelimitedListToSet(scope);

            if (!authorizedScopes.containsAll(requestedScopes)) {
                logger.error("message (Scopes not approved): "
                        + "authorizationCode=" + authorizationCode + ", "
                        + "responseType=" + responseType + ", "
                        + "clientId=" + clientId + ", "
                        + "redirectUri=" + redirectUri + ", "
                        + "scope=" + scope + ", "
                        + "authorizedScopes=" + authorizedScopes);
                model.addAttribute("userMessage", iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_SCOPES_NOT_APPROVED));
                return "error";
            }

            for (String requestedScope : StringUtils.delimitedListToStringArray(scope, " ")) {
                if (OidcScopes.OPENID.equals(requestedScope)) {
                    continue;
                }
                if (authorizedScopes.contains(requestedScope)) {
                    approvedScopes.add(requestedScope);
                }
            }
        }


        model.addAttribute("code", authorizationCode);
        model.addAttribute("clientId", clientId);
        model.addAttribute("scopes", withDescription(approvedScopes));
        model.addAttribute("principalName", principalName);
        model.addAttribute("redirectUri", redirectUri);
        model.addAttribute("consentRequestURI", "/oauth2/authorization");

        return "consent";
    }

    private static Set<ScopeWithDescription> withDescription(Set<String> scopes) {
        Set<ScopeWithDescription> scopeWithDescriptions = new HashSet<>();
        for (String scope : scopes) {
            scopeWithDescriptions.add(new ScopeWithDescription(scope));

        }
        return scopeWithDescriptions;
    }

    public static class ScopeWithDescription {
        private static final String DEFAULT_DESCRIPTION = "UNKNOWN SCOPE - We cannot provide information about this permission, use caution when granting this.";
        private static final Map<String, String> scopeDescriptions = new HashMap<>();
        static {
            scopeDescriptions.put(
                    OidcScopes.PROFILE,
                    "This application will be able to read your profile information."
            );
            scopeDescriptions.put(
                    "message.read",
                    "This application will be able to read your message."
            );
            scopeDescriptions.put(
                    "message.write",
                    "This application will be able to add new messages. It will also be able to edit and delete existing messages."
            );
            scopeDescriptions.put(
                    "user.read",
                    "This application will be able to read your user information."
            );
            scopeDescriptions.put(
                    "other.scope",
                    "This is another scope example of a scope description."
            );
        }

        public final String scope;
        public final String description;

        ScopeWithDescription(String scope) {
            this.scope = scope;
            this.description = scopeDescriptions.getOrDefault(scope, DEFAULT_DESCRIPTION);
        }
    }


}
