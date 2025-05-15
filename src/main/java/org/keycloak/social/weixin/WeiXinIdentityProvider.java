/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.social.weixin;

import java.io.IOException;
import java.net.URI;
import java.util.Objects;
import java.util.UUID;

import jakarta.ws.rs.core.*;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.social.weixin.egress.wechat.mp.WechatMpApi;
import org.keycloak.social.weixin.egress.wechat.mp.models.ActionInfo;
import org.keycloak.social.weixin.egress.wechat.mp.models.Scene;
import org.keycloak.social.weixin.egress.wechat.mp.models.TicketRequest;
import org.keycloak.social.weixin.helpers.UserAgentHelper;

public class WeiXinIdentityProvider extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig>
        implements SocialIdentityProvider<OAuth2IdentityProviderConfig> {
    private static final Logger wxlogger = Logger.getLogger(WeiXinIdentityProvider.class);

    private static final String TOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/access_token";

    public static final String OPEN_AUTH_URL = "https://open.weixin.qq.com/connect/qrconnect";
    public static final String OPEN_DEFAULT_SCOPE = "snsapi_login";
    public static final String OAUTH2_PARAMETER_CLIENT_ID = "appid";
    public static final String OAUTH2_PARAMETER_CLIENT_SECRET = "secret";

    public static final String OPEN_CLIENT_ID = "openClientId";
    public static final String OPEN_CLIENT_SECRET = "openClientSecret";
    public static final String OPEN_CLIENT_ENABLED = "openClientEnabled";

    public static final String WECHAT_MOBILE_AUTH_URL = "https://open.weixin.qq.com/connect/oauth2/authorize";
    public static final String WECHAT_MP_DEFAULT_SCOPE = "snsapi_userinfo";
    public static final String CUSTOMIZED_LOGIN_URL_FOR_PC = "customizedLoginUrl";
    public static final String WECHAT_MP_APP_ID = "clientId2";
    public static final String WECHAT_MP_APP_SECRET = "clientSecret2";

    public static final String WECHAT_MP_APP_TOKEN = "clientToken";

    public static final String PROFILE_URL = "https://api.weixin.qq.com/sns/userinfo?access_token=ACCESS_TOKEN&openid=OPENID&lang=zh_CN";

    public static final String WMP_APP_ID = "wmpClientId";
    public static final String WMP_APP_SECRET = "wmpClientSecret";
    public static final String WMP_AUTH_URL = "https://api.weixin.qq.com/sns/jscode2session";

    public static final String OPENID = "openid";
    public static final String WECHATFLAG = "micromessenger";
    public final WeixinIdentityCustomAuth customAuth;
    protected KeycloakSession session;

    public WeiXinIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(OPEN_AUTH_URL);
        config.setTokenUrl(TOKEN_URL);

        customAuth = new WeixinIdentityCustomAuth(session, config, this);
        this.session = session;
    }

    public WeiXinIdentityProvider(KeycloakSession session, WeixinIdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(OPEN_AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setUserInfoUrl(PROFILE_URL);

        customAuth = new WeixinIdentityCustomAuth(session, config, this);
        this.session = session;
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        wxlogger.info(String.format("callback event = %s", event));
        return new org.keycloak.social.weixin.Endpoint(this, callback, realm, event);
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        String unionId = getJsonProperty(profile, "unionid");
        var openId = getJsonProperty(profile, "openid");
        var nickname = getJsonProperty(profile, "nickname");
        var avatar = getJsonProperty(profile, "headimgurl");
        var externalUserId = unionId != null && !unionId.isEmpty() ? unionId : openId;

        BrokeredIdentityContext user = new BrokeredIdentityContext(externalUserId,super.getConfig());

        user.setUsername(externalUserId);
        user.setBrokerUserId(externalUserId);
        user.setModelUsername(externalUserId);
        user.setName(nickname);

        wxlogger.info("set user avatar to:" + avatar);
        user.setUserAttribute("avatar", avatar);
        //user.setIdpConfig(getConfig());
        user.setIdp(this);
        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());

        return user;
    }

    public BrokeredIdentityContext getFederatedIdentity(String response, WechatLoginType wechatLoginType, String response2) {
        var accessToken = wechatLoginType.equals(WechatLoginType.FROM_WECHAT_MINI_PROGRAM) ? extractTokenFromResponse(response2, getAccessTokenResponseParameter()) : extractTokenFromResponse(response, getAccessTokenResponseParameter());

        if (accessToken == null) {
            throw new IdentityBrokerException("No access token available in OAuth server response: " + response);
        }

        BrokeredIdentityContext context = null;
        try {
            JsonNode profile;
            if (WechatLoginType.FROM_WECHAT_BROWSER.equals(wechatLoginType) ||
                    WechatLoginType.FROM_PC_QR_CODE_SCANNING.equals(wechatLoginType)) {
                String openid = extractTokenFromResponse(response, OPENID);
                String url = PROFILE_URL.replace("ACCESS_TOKEN", accessToken).replace("OPENID", openid);
                profile = SimpleHttp.doGet(url, session).asJson();
            } else {
                profile = new ObjectMapper().readTree(response);
            }
            wxlogger.info("get userInfo =" + profile.toString());
            context = extractIdentityFromProfile(null, profile);
        } catch (IOException e) {
            wxlogger.error(e);
        }

        assert context != null;

        context.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);
        return context;
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        wxlogger.info(String.format("performing Login = %s", request != null && request.getUriInfo() != null ? request.getUriInfo().getAbsolutePath().toString() : "null"));
        try {
            URI authorizationUrl = createAuthorizationUrl(Objects.requireNonNull(request)).build();
            wxlogger.info(String.format("authorizationUrl = %s", authorizationUrl.toString()));

            String ua = request.getSession().getContext().getRequestHeaders().getHeaderString("user-agent").toLowerCase();
            wxlogger.info(String.format("user-agent = %s", ua));

            if (UserAgentHelper.isWechatBrowser(ua)) {
                URI location = URI.create(String.format("%s#wechat_redirect", authorizationUrl));
                wxlogger.info(String.format("see other %s", location));

                return Response.seeOther(location).build();
            }

            wxlogger.info(String.format("see other %s", authorizationUrl));

            return Response.seeOther(authorizationUrl).build();
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not create authentication request because " + e,
                    e);
        }
    }

    @Override
    protected String getDefaultScopes() {
        return OPEN_DEFAULT_SCOPE;
    }


    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        final UriBuilder uriBuilder;
        String ua = request.getSession().getContext().getRequestHeaders().getHeaderString("user-agent").toLowerCase();
        wxlogger.info(String.format("creating auth url from %s", ua));

        if (UserAgentHelper.isWechatBrowser(ua)) {// 是微信浏览器
            wxlogger.info("----------wechat");
            uriBuilder = UriBuilder.fromUri(WECHAT_MOBILE_AUTH_URL);
            uriBuilder.queryParam(OAUTH2_PARAMETER_SCOPE, WECHAT_MP_DEFAULT_SCOPE)
                    .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
                    .queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, "code")
                    .queryParam(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId())
                    .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri());

            return uriBuilder;
        } else {
            var config = getConfig();
            if (config instanceof WeixinIdentityProviderConfig) {
                var customizedLoginUrlForPc = ((WeixinIdentityProviderConfig) config).getCustomizedLoginUrlForPc();
                if (config.getConfig().get(OPEN_CLIENT_ENABLED) != null && config.getConfig().get(OPEN_CLIENT_ENABLED).equals("true")) {
                    wxlogger.info("----------open client enabled");
                    if (customizedLoginUrlForPc!=null){
                        uriBuilder = UriBuilder.fromUri(customizedLoginUrlForPc);
                    }else {
                        uriBuilder = UriBuilder.fromUri(OPEN_AUTH_URL);
                    }

                    uriBuilder.queryParam(OAUTH2_PARAMETER_SCOPE, OPEN_DEFAULT_SCOPE)
                            .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
                            .queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, "code")
                            .queryParam(OAUTH2_PARAMETER_CLIENT_ID, config.getConfig().get(OPEN_CLIENT_ID))
                            .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri());

                    return uriBuilder;
                }

                if (customizedLoginUrlForPc != null && !customizedLoginUrlForPc.isEmpty()) {
                    wxlogger.info("----------customized login url for pc");
                    wxlogger.info("clientId: " + config.getConfig().get(WECHAT_MP_APP_ID));
                    wxlogger.info("state: " + request.getState().getEncoded());

                    uriBuilder = UriBuilder.fromUri(customizedLoginUrlForPc);

                    uriBuilder.queryParam(OAUTH2_PARAMETER_SCOPE, WECHAT_MP_DEFAULT_SCOPE)
                            .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
                            .queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, "code")
                            .queryParam(OAUTH2_PARAMETER_CLIENT_ID, config.getConfig().get(WECHAT_MP_APP_ID))
                            .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri());

                    return uriBuilder;
                } else {
                    wxlogger.info("未启用开放平台，且未配置自定义登录页面，则返回一个 html 页面，展示带参二维码");
                    uriBuilder = UriBuilder.fromUri("/realms/" + request.getRealm().getName() + "/QrCodeResourceProviderFactory/mp-qr");

                    var wechatApi = new WechatMpApi(
                            config.getConfig().get(WECHAT_MP_APP_ID),
                            config.getConfig().get(WECHAT_MP_APP_SECRET),
                            session,
                            request.getAuthenticationSession()
                    );

                    var ticket = wechatApi.createTmpQrCode(new TicketRequest(2592000, "QR_STR_SCENE", new ActionInfo(new Scene("1")))).ticket;
                    wxlogger.info("ticket = " + ticket);

                    uriBuilder
                            .queryParam("ticket", ticket)
                            .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
                            .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri())
                            .queryParam("qr-code-url", "https://mp.weixin.qq.com/cgi-bin/showqrcode?ticket=" + ticket)
                    ;
                }
            } else {
                wxlogger.info("----------default");
                wxlogger.info("clientId: " + config.getClientId());
                uriBuilder = UriBuilder.fromUri(config.getAuthorizationUrl());
                uriBuilder.queryParam(OAUTH2_PARAMETER_SCOPE, config.getDefaultScope())
                        .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
                        .queryParam(OAUTH2_PARAMETER_CLIENT_ID, config.getClientId())
                        .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri());
            }
        }

        String loginHint = request.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
        wxlogger.info("loginHint = " + loginHint);
        if (getConfig().isLoginHint() && loginHint != null) {
            uriBuilder.queryParam(OIDCLoginProtocol.LOGIN_HINT_PARAM, loginHint);
        }

        String prompt = getConfig().getPrompt();
        if (prompt == null || prompt.isEmpty()) {
            prompt = request.getAuthenticationSession().getClientNote(OAuth2Constants.PROMPT);
        }
        if (prompt != null) {
            uriBuilder.queryParam(OAuth2Constants.PROMPT, prompt);
        }

        String nonce = request.getAuthenticationSession().getClientNote(OIDCLoginProtocol.NONCE_PARAM);
        if (nonce == null || nonce.isEmpty()) {
            nonce = UUID.randomUUID().toString();
            request.getAuthenticationSession().setClientNote(OIDCLoginProtocol.NONCE_PARAM, nonce);
        }
        uriBuilder.queryParam(OIDCLoginProtocol.NONCE_PARAM, nonce);

        String acr = request.getAuthenticationSession().getClientNote(OAuth2Constants.ACR_VALUES);
        if (acr != null) {
            uriBuilder.queryParam(OAuth2Constants.ACR_VALUES, acr);
        }

        return uriBuilder;
    }

}
