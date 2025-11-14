package org.keycloak.social.weixin;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class OAuth2WeiXinIdentityProviderFactory extends AbstractIdentityProviderFactory<OAuth2WeiXinIdentityProvider> implements
    SocialIdentityProviderFactory<OAuth2WeiXinIdentityProvider> {

    public static final String PROVIDER_ID = "weixin-oauth2";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getName() {
        return "WeiXin OAuth2";
    }

    @Override
    public OAuth2WeiXinIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new OAuth2WeiXinIdentityProvider(session, new OAuth2IdentityProviderConfig(model));
    }

    @Override
    public OAuth2IdentityProviderConfig createConfig() {
        return new OAuth2IdentityProviderConfig();
    }

}