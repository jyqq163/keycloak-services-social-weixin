package org.keycloak.social.weixin;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.models.KeycloakSession;

public class WeiXinIdentityProvider extends OAuth2WeiXinIdentityProvider
    implements SocialIdentityProvider<OAuth2IdentityProviderConfig> {

    public static final String AUTH_URL = "https://open.weixin.qq.com/connect/qrconnect";
    public static final String TOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/access_token";
    public static final String PROFILE_URL = "https://api.weixin.qq.com/sns/userinfo?access_token=ACCESS_TOKEN&openid=OPENID&lang=zh_CN";

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }

    public WeiXinIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setUserInfoUrl(PROFILE_URL);
    }

}
