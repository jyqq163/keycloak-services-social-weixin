package org.keycloak.social.weixin;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.KeycloakSession;

public class WeiXinIdentityProviderFactory extends AbstractIdentityProviderFactory<WeiXinIdentityProvider>
        implements SocialIdentityProviderFactory<WeiXinIdentityProvider> {

    public static final String PROVIDER_ID = "weixin";

    @Override
    public String getName() {
        return "微信";
    }

    @Override
    public WeiXinIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new WeiXinIdentityProvider(session, new WeixinProviderConfig(model));
    }

    @Override
    public WeixinProviderConfig createConfig() {
        return new WeixinProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }


}
