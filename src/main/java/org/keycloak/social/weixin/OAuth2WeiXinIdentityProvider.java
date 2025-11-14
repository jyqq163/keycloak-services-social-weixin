package org.keycloak.social.weixin;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.core.UriBuilder;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.util.Time;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

public class OAuth2WeiXinIdentityProvider extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig>
    implements SocialIdentityProvider<OAuth2IdentityProviderConfig> {

    public static final String OAUTH2_PARAMETER_CLIENT_ID = "appid";
    public static final String OAUTH2_PARAMETER_CLIENT_SECRET = "secret";
    public static final String DEFAULT_SCOPE = "snsapi_login";
    public static final String OPENID = "openid";
    public static final String CACHE_OPENID = "weixin_openid";

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }

    public OAuth2WeiXinIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
        super(session, config);
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Endpoint(callback, realm, event, this);
    }

    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        UriBuilder uriBuilder = super.createAuthorizationUrl(request);
        uriBuilder.queryParam(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId());
        return uriBuilder;
    }

    @Override
    public SimpleHttpRequest authenticateTokenRequest(SimpleHttpRequest tokenRequest) {
        SimpleHttpRequest simpleHttp = super.authenticateTokenRequest(tokenRequest);
        tokenRequest.param(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId()).param(OAUTH2_PARAMETER_CLIENT_SECRET, getConfig().getClientSecret());
        return simpleHttp;
    }

    @Override
    public BrokeredIdentityContext getFederatedIdentity(String response) {
        String accessToken = extractTokenFromResponse(response, getAccessTokenResponseParameter());
        if (accessToken == null) {
            throw new IdentityBrokerException("No access token available in OAuth server response: " + response);
        }
        String openid = extractTokenFromResponse(response, OPENID);
        if (openid == null) {
            throw new IdentityBrokerException("No openid available in OAuth server response: " + response);
        }
        session.setAttribute(CACHE_OPENID, extractTokenFromResponse(response, OPENID));

        BrokeredIdentityContext context = doGetFederatedIdentity(accessToken);

        if (getConfig().isStoreToken() && response.startsWith("{")) {
            try {
                OAuthResponse tokenResponse = JsonSerialization.readValue(response, OAuthResponse.class);
                if (tokenResponse.getExpiresIn() != null && tokenResponse.getExpiresIn() > 0) {
                    long accessTokenExpiration = Time.currentTime() + tokenResponse.getExpiresIn();
                    tokenResponse.setAccessTokenExpiration(accessTokenExpiration);
                    response = JsonSerialization.writeValueAsString(tokenResponse);
                }
                context.setToken(response);
            } catch (IOException e) {
                logger.debugf("Can't store expiration date in JSON token", e);
            }
        }

        context.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);
        return context;
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        String openId = (String)session.getAttribute(CACHE_OPENID);
        if (accessToken == null || openId == null) {
            throw new IdentityBrokerException("Missing access token or openid");
        }

        try (SimpleHttpResponse response = SimpleHttp.create(session).doGet(getConfig().getUserInfoUrl()).param(getAccessTokenResponseParameter(), accessToken)
            .param(OPENID, openId).asResponse()) {

            JsonNode userInfo = response.asJson();
            String unionid = getJsonProperty(userInfo, "unionid");
            String userId = (unionid != null && !unionid.isEmpty()) ? unionid : openId;

            BrokeredIdentityContext identity = new BrokeredIdentityContext(userId, getConfig());

            // 设置用户属性
            populateIdentityAttributes(identity, userInfo);

            identity.setIdp(this);
            return identity;

        } catch (Exception e) {
            throw new IdentityBrokerException("Error while fetching user profile", e);
        }
    }

    protected void populateIdentityAttributes(BrokeredIdentityContext identity, JsonNode userInfo) {
        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(identity, userInfo, getConfig().getAlias());

        String givenName = getJsonProperty(userInfo, getConfig().getGivenNameClaim());
        if (givenName != null) {
            identity.setFirstName(givenName);
        }

        String familyName = getJsonProperty(userInfo, getConfig().getFamilyNameClaim());
        if (familyName != null) {
            identity.setLastName(familyName);
        }

        if (givenName == null && familyName == null) {
            String name = getJsonProperty(userInfo, getConfig().getFullNameClaim());
            identity.setName(name);
        }

        String email = getJsonProperty(userInfo, getConfig().getEmailClaim());
        identity.setEmail(email);

        identity.setBrokerUserId(getConfig().getAlias() + "." + identity.getId());

        String preferredUsername = getJsonProperty(userInfo, getConfig().getUserNameClaim());
        if (preferredUsername == null) {
            preferredUsername = email != null ? email : identity.getId();
        }
        identity.setUsername(preferredUsername);
    }
}
