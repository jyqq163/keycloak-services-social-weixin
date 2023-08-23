package org.keycloak.social.weixin;

import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.models.KeycloakSession;

import java.io.IOException;

import static org.keycloak.social.weixin.UserAgentHelper.isWechatBrowser;
import static org.keycloak.social.weixin.WeiXinIdentityProvider.WECHAT_MP_APP_ID;
import static org.keycloak.social.weixin.WeiXinIdentityProvider.WECHAT_MP_APP_SECRET;

public class WeixinIdentityCustomAuth extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig>
        implements SocialIdentityProvider<OAuth2IdentityProviderConfig> {

    private final WeiXinIdentityProvider weiXinIdentityProvider;
    public String accessToken;

    public WeixinIdentityCustomAuth(KeycloakSession session, OAuth2IdentityProviderConfig config, WeiXinIdentityProvider weiXinIdentityProvider) {
        super(session, config);
        this.weiXinIdentityProvider = weiXinIdentityProvider;
    }

    // TODO: cache mechanism
    public String getAccessToken() throws IOException {
        var clientId = this.getConfig().getClientId();
        var clientSecret = this.getConfig().getClientSecret();

        try {
            String ua = session.getContext().getRequestHeaders().getHeaderString("user-agent").toLowerCase();

            if (isWechatBrowser(ua)) {
                clientId = this.getConfig().getConfig().get(WECHAT_MP_APP_ID);
                clientSecret = this.getConfig().getConfig().get(WECHAT_MP_APP_SECRET);
            }
        } catch (Exception ex) {
            logger.error(ex);
        }

        logger.info(String.format("getAccessToken by %s%n%s%n", clientId, clientSecret));
        var res =
                SimpleHttp.doGet(String.format("https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential" +
                                "&appid=%s&secret=%s", this.getConfig().getClientId(), this.getConfig().getClientSecret()),
                        this.session).asString();

        logger.info(String.format("res is %s%n", res));
        var accessToken = this.extractTokenFromResponse(res, "access_token");
//        var expiresIn = this.extractTokenFromResponse(res, "expires_in");

        this.accessToken = accessToken;
        return accessToken;
    }

    @Override
    protected String getDefaultScopes() {
        return null;
    }

    public BrokeredIdentityContext auth(String openid) throws IOException {
        var accessToken = getAccessToken();

        var profile = SimpleHttp.doGet(String.format("https://api.weixin.qq.com/cgi-bin/user/info?access_token=%s&openid" +
                "=%s&lang=zh_CN", accessToken, openid), this.session).asJson();

        System.out.println("profile is " + profile);

        var context = this.weiXinIdentityProvider.extractIdentityFromProfile(null, profile);
        context.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);

        return context;
    }
}
