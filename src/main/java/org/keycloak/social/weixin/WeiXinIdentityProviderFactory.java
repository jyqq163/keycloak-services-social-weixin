package org.keycloak.social.weixin;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ConfiguredProvider;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

public class WeiXinIdentityProviderFactory extends AbstractIdentityProviderFactory<WeiXinIdentityProvider>
        implements SocialIdentityProviderFactory<WeiXinIdentityProvider>, ConfiguredProvider {

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

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property().name(WeiXinIdentityProvider.CUSTOMIZED_LOGIN_URL_FOR_PC)
                .label("PC端自定义登录URL")
                .helpText("PC端自定义登录URL")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .build();
    }

    @Override
    public String getHelpText() {
        return "微信登录集成";
    }
}
