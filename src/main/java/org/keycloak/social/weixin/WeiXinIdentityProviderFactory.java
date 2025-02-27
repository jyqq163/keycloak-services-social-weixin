package org.keycloak.social.weixin;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
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
        return "微信二维码登录";
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
                .property().name(WeiXinIdentityProvider.WECHAT_MP_APP_ID)
                .label("PC 用的公众号 App Id")
                .helpText("当用户使用 PC 进行关注微信公众号即登录时，要使用的 app Id，即微信公众号（不是开放平台）的 appid。可以和上面的 Client ID 一样，也可以不一样")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(WeiXinIdentityProvider.WECHAT_MP_APP_SECRET)
                .label("PC 用的公众号 App Secret")
                .helpText("当用户使用 PC 进行关注微信公众号即登录时，要使用的 app Secret，即微信公众号（不是开放平台）的 app secret。可以和上面的 Client Secret 一样，也可以不一样")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()

                .property().name(WeiXinIdentityProvider.CUSTOMIZED_LOGIN_URL_FOR_PC)
                .label("PC 登录 URL")
                .helpText("PC 登录 URL 的登录页面，可以配置为一个自定义的前端登录页面，用来展示公众号带参二维码")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()

                .property().name(WeiXinIdentityProvider.OPEN_CLIENT_ID)
                .label("开放平台 Client ID")
                .helpText("当用户使用微信开放平台登录时，要使用的 Client ID，即微信开放平台的 appid")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(WeiXinIdentityProvider.OPEN_CLIENT_SECRET)
                .label("开放平台 Client Secret")
                .helpText("当用户使用微信开放平台登录时，要使用的 Client Secret，即微信开放平台的 app secret")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(WeiXinIdentityProvider.OPEN_CLIENT_ENABLED)
                .label("是否启用开放平台登录")
                .helpText("是否启用开放平台登录，默认不启用，即使用关注公众号的方式登录。如果启用，则使用开放平台的方式登录")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .add()

                .property().name(WeiXinIdentityProvider.WMP_APP_ID)
                .label("小程序 appId")
                .helpText("小程序的 appid")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .property().name(WeiXinIdentityProvider.WMP_APP_SECRET)
                .label("小程序 appSecret")
                .helpText("小程序的 app secret")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()

                .build();
    }
}
