package org.keycloak.social.weixin;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.Response;
import org.junit.*;
import org.junit.jupiter.api.Assertions;
import org.junit.runner.RunWith;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.social.weixin.mock.MockedAuthenticationSessionModel;
import org.keycloak.social.weixin.mock.MockedHttpRequest;

import java.util.Map;
import java.util.UUID;

import org.keycloak.social.weixin.mock.MockedKeycloakSession;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import static org.hamcrest.CoreMatchers.containsString;

@RunWith(PowerMockRunner.class)
@PrepareForTest({UUID.class, WeiXinIdentityProvider.class})
public class WeiXinIdentityProviderTest {
    WeiXinIdentityProvider weiXinIdentityProvider;

    @Before
    public void before() {
        UUID uuid = PowerMockito.mock(UUID.class);
        Mockito.when(uuid.toString()).thenReturn("ccec3eea-fd08-4ca2-b83a-2921228f2480");

        PowerMockito.mockStatic(UUID.class);
        PowerMockito.when(UUID.randomUUID()).thenReturn(uuid);

        OAuth2IdentityProviderConfig config = new OAuth2IdentityProviderConfig();
        config.setClientId("clientId");
        weiXinIdentityProvider = new WeiXinIdentityProvider(null, config);
    }

    @Test
    public void performLoginThrowsIfHttpRequestIsNull() {
        try {
            AuthenticationRequest request = new AuthenticationRequest(null, null, null, null, null, null, null);

            weiXinIdentityProvider.performLogin(request);
        } catch (RuntimeException ex) {
            Assert.assertThat(ex.toString(), containsString("org.keycloak.broker.provider.IdentityBrokerException: Could not create authentication request because java.lang.NullPointerException"));
        }
    }

    @Test
    public void pcGoesToQRConnect() {
        IdentityBrokerState state = IdentityBrokerState.decoded("state", "clientId", "clientId", "tabId", null);

        var authSession = new MockedAuthenticationSessionModel();

        org.keycloak.http.HttpRequest httpRequest = new MockedHttpRequest();
        AuthenticationRequest request = new AuthenticationRequest(new MockedKeycloakSession(httpRequest), null, authSession, httpRequest, null, state, "https" +
                "://redirect.to.customized/url");

        var res = weiXinIdentityProvider.performLogin(request);
        Assert.assertEquals("303 redirect", Response.Status.SEE_OTHER.getStatusCode(), res.getStatus());
        Assert.assertEquals("pc goes to customized login url", "https://open.weixin.qq" +
                ".com/connect/qrconnect?scope=snsapi_login&state=state.tabId" +
                ".Y2xpZW50SWQ&appid=clientId&redirect_uri=https%3A%2F%2Fredirect.to" +
                ".customized%2Furl&nonce=ccec3eea-fd08-4ca2-b83a-2921228f2480", res.getLocation().toString());
    }

    @Test
    public void pcGoesToCustomizedURLIfPresent() {
        var config = new WeixinIdentityProviderConfig();
        config.setClientId("clientId");
        config.setClientId2(WeiXinIdentityProvider.WECHAT_MP_APP_ID);
        config.setCustomizedLoginUrlForPc("https://another.url/path");

        Assert.assertEquals("set config get config", "https://another.url/path", config.getCustomizedLoginUrlForPc());

        weiXinIdentityProvider = new WeiXinIdentityProvider(null, config);

        IdentityBrokerState state = IdentityBrokerState.decoded("state", "clientId", "clientId", "tabId", null);
        var authSession = new MockedAuthenticationSessionModel();

        org.keycloak.http.HttpRequest httpRequest = new MockedHttpRequest();
        AuthenticationRequest request = new AuthenticationRequest(new MockedKeycloakSession(httpRequest), null, authSession, httpRequest, null, state,
                "https" +
                        "://redirect.to.customized/url");

        var res = weiXinIdentityProvider.performLogin(request);

        Assert.assertEquals("303 redirect", Response.Status.SEE_OTHER.getStatusCode(), res.getStatus());
        Assert.assertTrue("pc goes to customized login url", res.getLocation().toString().startsWith("https://another.url/path"));
    }

    @org.junit.jupiter.api.Test
    void getFederatedIdentityForWMP() throws JsonProcessingException {
        var mockSessionKey = "n1HE228Kq\\/i3HRlz\\/K71Aw==";
        var mockUserInfo = Map.of("session_key", mockSessionKey);

        var mockAccessToken = "54_XzDD7MVKpVBX5m-VtsjAE9tyImVxUSKE2VgOzEBDemngNCAVwFfPr3RNusGjcBrZl2CPyQoONP4kqUI24Wl1KYZO-ZC2emmLR1bZfUPoH2FXd5iz780ZTOhb3lkDjK8zS0n31JdhXPwtPaqVDKHeAAAMTQ";
        var expectedContextData = Map.of(IdentityProvider.FEDERATED_ACCESS_TOKEN, mockAccessToken, "UserInfo", mockUserInfo);

        final String sessionKeyResponse = "{\"session_key\":\"n1HE228Kq\\/i3HRlz\\/K71Aw==\",\"openid\":\"odrHN4p1UMWRdQfMK4xm9dtQXvf8\",\"unionid\":\"oLLUdsyyVLcjdxFXiOV2pZYuOdR0\"}";
        var expectedJsonProfile = new ObjectMapper().readTree(sessionKeyResponse);

        var config = new WeixinIdentityProviderConfig();
        config.setWmpClientId("123456");

        var sut = new WeiXinIdentityProvider(null, config);

        var expectedUser = new BrokeredIdentityContext(sut.getJsonProperty(expectedJsonProfile, "unionid"), sut.getConfig());
        expectedUser.setUsername(sut.getJsonProperty(expectedJsonProfile, "openid"));
        expectedUser.setEmail("null");

        var res = sut.getFederatedIdentity(sessionKeyResponse, WechatLoginType.FROM_WECHAT_MINI_PROGRAM, "{\"access_token\":\"" + mockAccessToken + "\",\"expires_in\":7200}");
        var contextData = res.getContextData();
        Assertions.assertNotNull(contextData);
        Assertions.assertEquals(expectedContextData.get(IdentityProvider.FEDERATED_ACCESS_TOKEN), contextData.get(IdentityProvider.FEDERATED_ACCESS_TOKEN));
        Assertions.assertEquals(expectedUser.toString(), res.toString());
    }
}
