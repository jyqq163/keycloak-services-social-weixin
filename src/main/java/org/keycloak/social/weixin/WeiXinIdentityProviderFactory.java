package org.keycloak.social.weixin;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

public class WeiXinIdentityProviderFactory extends
        AbstractIdentityProviderFactory<WeiXinIdentityProvider> implements
        SocialIdentityProviderFactory<WeiXinIdentityProvider> {

    public static final String PROVIDER_ID = "weixin";

    @Override
    public String getName() {
        return "微信";
    }

    @Override
    public WeiXinIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new WeiXinIdentityProvider(session, new WeixinIdentityProviderConfig(model));
    }

    @Override
    public OAuth2IdentityProviderConfig createConfig() {
        return new OAuth2IdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }


    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property().name(WeiXinIdentityProvider.WECHAT_APPID_KEY)
                .label("手机端微信 App Id")
                .helpText("当用户使用手机进行微信登录时，要使用的 app Id")
                .add()
                .property().name(WeiXinIdentityProvider.WECHAT_APPID_SECRET)
                .label("手机端微信 App Secret")
                .helpText("当用户使用手机进行微信登录时，要使用的 app Secret")
                .add()

                .property().name(WeiXinIdentityProvider.CUSTOMIZED_LOGIN_URL_FOR_PC)
                .label("PC 登录 URL")
                .helpText("PC 登录 URL 的登录页面，可以配置为一个自定义的前端登录页面")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add().build();
    }
}
