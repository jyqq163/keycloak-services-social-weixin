package org.keycloak.social.weixin;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;
import org.keycloak.social.weixin.helpers.UserAgentHelper;
import org.keycloak.social.weixin.helpers.WMPHelper;

import java.util.Map;
import java.util.Objects;

public class Endpoint extends WeiXinIdentityProvider {
    private final WeiXinIdentityProvider weiXinIdentityProvider;
    protected IdentityProvider.AuthenticationCallback callback;
    protected RealmModel realm;
    protected EventBuilder event;

    @Context
    protected ClientConnection clientConnection;

    @Context
    protected org.keycloak.http.HttpRequest request;

    public Endpoint(WeiXinIdentityProvider weiXinIdentityProvider, IdentityProvider.AuthenticationCallback callback, RealmModel realm, EventBuilder event) {
        super(weiXinIdentityProvider.session, weiXinIdentityProvider.getConfig());

        this.weiXinIdentityProvider = weiXinIdentityProvider;
        this.callback = callback;
        this.realm = realm;
        this.event = event;
    }

    @GET
    public Response authResponse(@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
                                 @QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode, @QueryParam(OAuth2Constants.ERROR) String error, @QueryParam(OAuth2Constants.SCOPE_OPENID) String openid, @QueryParam("clientId") String clientId, @QueryParam("tabId") String tabId) {
        AbstractOAuth2IdentityProvider.logger.info(String.format("OAUTH2_PARAMETER_CODE = %s, %s, %s, %s, %s", authorizationCode, error, openid, clientId, tabId));
        var wechatLoginType = WechatLoginType.FROM_PC_QR_CODE_SCANNING;

        String ua = weiXinIdentityProvider.session.getContext().getRequestHeaders().getHeaderString("user-agent").toLowerCase();
        if (UserAgentHelper.isWechatBrowser(ua)) {
            AbstractOAuth2IdentityProvider.logger.info("user-agent=wechat");
            wechatLoginType = WechatLoginType.FROM_WECHAT_BROWSER;
        }

        if (error != null) {
            if (error.equals(AbstractOAuth2IdentityProvider.ACCESS_DENIED)) {
                AbstractOAuth2IdentityProvider.logger.error(AbstractOAuth2IdentityProvider.ACCESS_DENIED + " for broker login " + weiXinIdentityProvider.getConfig().getProviderId() + " " + state);
                return callback.cancelled(weiXinIdentityProvider.getConfig());
            } else {
                AbstractOAuth2IdentityProvider.logger.error(error + " for broker login " + weiXinIdentityProvider.getConfig().getProviderId());
                return callback.error(state + " " + Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            }
        }

        try {
            BrokeredIdentityContext federatedIdentity;

            if (openid != null) {
                // TODO: use ticket here instead, and then use this ticket to get openid from sso.jiwai.win
                federatedIdentity = weiXinIdentityProvider.customAuth.auth(openid, wechatLoginType);

                setFederatedIdentity(state, federatedIdentity, weiXinIdentityProvider.customAuth.accessToken);

                return authenticated(federatedIdentity);
            }

            if (authorizationCode != null) {
                if (state == null) {
                    wechatLoginType = WechatLoginType.FROM_WECHAT_MINI_PROGRAM;
                    AbstractOAuth2IdentityProvider.logger.info("response from wmp with code = " + authorizationCode);
                }

                var responses = generateTokenRequest(authorizationCode, wechatLoginType);
                var response = responses[0].asString();
                var accessTokenResponse = responses[1] != null ? responses[1].asString() : "";
                AbstractOAuth2IdentityProvider.logger.info("response from auth code = " + response + ", " + accessTokenResponse);
                federatedIdentity = weiXinIdentityProvider.getFederatedIdentity(response, wechatLoginType, accessTokenResponse);

                setFederatedIdentity(Objects.requireNonNullElse(state, WMPHelper.createStateForWMP(clientId, tabId)), federatedIdentity, response);

                return authenticated(federatedIdentity);
            }
        } catch (WebApplicationException e) {
            return e.getResponse();
        } catch (Exception e) {
            AbstractOAuth2IdentityProvider.logger.error("Failed to make identity provider (weixin) oauth callback", e);
        }
        event.event(EventType.LOGIN);
        event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
        return ErrorPage.error(weiXinIdentityProvider.session, null, Response.Status.BAD_GATEWAY,
                Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
    }

    private Response authenticated(BrokeredIdentityContext federatedIdentity) {
        var weiXinIdentityBrokerService =
                new WeiXinIdentityBrokerService(realm);
        weiXinIdentityBrokerService.init(weiXinIdentityProvider.session, clientConnection, event, request);

        return weiXinIdentityBrokerService.authenticated(federatedIdentity);
    }

    public void setFederatedIdentity(@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state, BrokeredIdentityContext federatedIdentity, String accessToken) {
        if (weiXinIdentityProvider.getConfig().isStoreToken()) {
            if (federatedIdentity.getToken() == null)
                federatedIdentity.setToken(accessToken);
        }

        federatedIdentity.setIdpConfig(weiXinIdentityProvider.getConfig());
        federatedIdentity.setIdp(weiXinIdentityProvider);
        federatedIdentity.setContextData(Map.of("state", Objects.requireNonNullElse(state, "wmp")));
    }

    public SimpleHttp[] generateTokenRequest(String authorizationCode, WechatLoginType wechatLoginType) {
        AbstractOAuth2IdentityProvider.logger.info(String.format("generateTokenRequest, code = %s, loginType = %s", authorizationCode, wechatLoginType));
        if (WechatLoginType.FROM_WECHAT_BROWSER.equals(wechatLoginType)) {
            var mobileMpClientId = weiXinIdentityProvider.getConfig().getClientId();
            var mobileMpClientSecret = weiXinIdentityProvider.getConfig().getClientSecret();

            AbstractOAuth2IdentityProvider.logger.info(String.format("from wechat browser, posting to %s for fetching token, with mobileMpClientId = %s, mobileMpClientSecret = %s", weiXinIdentityProvider.getConfig().getTokenUrl(), mobileMpClientId, mobileMpClientSecret));

            return new SimpleHttp[]{SimpleHttp.doPost(weiXinIdentityProvider.getConfig().getTokenUrl(), weiXinIdentityProvider.session)
                    .param(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE, authorizationCode)
                    .param(WeiXinIdentityProvider.OAUTH2_PARAMETER_CLIENT_ID, mobileMpClientId)
                    .param(WeiXinIdentityProvider.OAUTH2_PARAMETER_CLIENT_SECRET, mobileMpClientSecret)
                    .param(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_REDIRECT_URI, weiXinIdentityProvider.getConfig().getConfig().get(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_REDIRECT_URI))
                    .param(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_GRANT_TYPE, AbstractOAuth2IdentityProvider.OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE), null};
        }

        if (WechatLoginType.FROM_WECHAT_MINI_PROGRAM.equals(wechatLoginType)) {
            AbstractOAuth2IdentityProvider.logger.info(String.format("from wechat mini program, posting to %s", WeiXinIdentityProvider.WMP_AUTH_URL));
            var wechatSession = SimpleHttp.doGet(WeiXinIdentityProvider.WMP_AUTH_URL, weiXinIdentityProvider.session).param(WeiXinIdentityProvider.OAUTH2_PARAMETER_CLIENT_ID, weiXinIdentityProvider.getConfig().getConfig().get(WeiXinIdentityProvider.WMP_APP_ID)).param(WeiXinIdentityProvider.OAUTH2_PARAMETER_CLIENT_SECRET, weiXinIdentityProvider.getConfig().getConfig().get(WeiXinIdentityProvider.WMP_APP_SECRET)).param("js_code", authorizationCode).param(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_GRANT_TYPE, AbstractOAuth2IdentityProvider.OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);

            var tokenRes = SimpleHttp.doGet(String.format("https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential" +
                            "&appid=%s&secret=%s", weiXinIdentityProvider.getConfig().getConfig().get(WeiXinIdentityProvider.WMP_APP_ID), weiXinIdentityProvider.getConfig().getConfig().get(WeiXinIdentityProvider.WMP_APP_SECRET)),
                    weiXinIdentityProvider.session);

            return new SimpleHttp[]{wechatSession, tokenRes};
        }

        var isOpenClientEnabled = weiXinIdentityProvider.getConfig().getConfig().get(WeiXinIdentityProvider.OPEN_CLIENT_ENABLED);

        if (isOpenClientEnabled.equals("true")) {
            return new SimpleHttp[]{SimpleHttp.doPost(weiXinIdentityProvider.getConfig().getTokenUrl(), weiXinIdentityProvider.session).param(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE, authorizationCode)
                    .param(WeiXinIdentityProvider.OAUTH2_PARAMETER_CLIENT_ID, weiXinIdentityProvider.getConfig().getConfig().get(WeiXinIdentityProvider.OPEN_CLIENT_ID))
                    .param(WeiXinIdentityProvider.OAUTH2_PARAMETER_CLIENT_SECRET, weiXinIdentityProvider.getConfig().getConfig().get(WeiXinIdentityProvider.OPEN_CLIENT_SECRET))
                    .param(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_REDIRECT_URI, weiXinIdentityProvider.getConfig().getConfig().get(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_REDIRECT_URI))
                    .param(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_GRANT_TYPE, AbstractOAuth2IdentityProvider.OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE), null};
        }

        return new SimpleHttp[]{SimpleHttp.doPost(weiXinIdentityProvider.getConfig().getTokenUrl(), weiXinIdentityProvider.session).param(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE, authorizationCode)
                .param(WeiXinIdentityProvider.OAUTH2_PARAMETER_CLIENT_ID, weiXinIdentityProvider.getConfig().getClientId())
                .param(WeiXinIdentityProvider.OAUTH2_PARAMETER_CLIENT_SECRET, weiXinIdentityProvider.getConfig().getClientSecret())
                .param(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_REDIRECT_URI, weiXinIdentityProvider.getConfig().getConfig().get(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_REDIRECT_URI))
                .param(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_GRANT_TYPE, AbstractOAuth2IdentityProvider.OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE), null};
    }
}
