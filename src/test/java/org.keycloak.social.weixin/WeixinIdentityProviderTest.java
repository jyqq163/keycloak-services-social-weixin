package org.keycloak.social.weixin;

import org.junit.*;

public class WeixinIdentityProviderTest {
    WeiXinIdentityProvider weiXinIdentityProvider;

    @BeforeClass
    public static void beforeClass() {

    }

    @Before
    public void before() {
        weiXinIdentityProvider = new WeiXinIdentityProvider(null, new org.keycloak.broker.oidc.OAuth2IdentityProviderConfig());
    }

    @AfterClass
    public static void afterClass() {

    }

    @After
    public void after() {

    }

    @Test
    public void pcGoesToCustomizedLoginUrl() {
//        Assert.assertEquals("pc goes to customized login url", "", weiXinIdentityProvider.performLogin());
    }
}