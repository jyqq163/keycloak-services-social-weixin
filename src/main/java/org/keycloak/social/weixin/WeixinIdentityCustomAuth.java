package org.keycloak.social.weixin;

import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.models.KeycloakSession;

import java.io.IOException;

public class WeixinIdentityCustomAuth extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig>
        implements SocialIdentityProvider<OAuth2IdentityProviderConfig> {

    private WeiXinIdentityProvider weiXinIdentityProvider;
    public String accessToken;

    public WeixinIdentityCustomAuth(KeycloakSession session, OAuth2IdentityProviderConfig config, WeiXinIdentityProvider weiXinIdentityProvider) {
        super(session, config);
        this.weiXinIdentityProvider = weiXinIdentityProvider;
    }

    // TODO: cache mechanism
    public String getAccessToken() throws IOException {
        var res =
                SimpleHttp.doGet(String.format("https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential" +
                                "&appid=%s&secret=%s", this.getConfig().getClientId(), this.getConfig().getClientSecret()),
                        this.session).asString();

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

        return this.weiXinIdentityProvider.extractIdentityFromProfile(null, profile);
    }
}
