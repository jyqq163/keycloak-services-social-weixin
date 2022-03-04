package org.keycloak.social.weixin;

import org.junit.Assert;
import org.junit.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.social.weixin.mock.MockedKeycloakSession;

import java.util.Map;

public class UtilTest {
    @Test
    public void inspectBrokeredIdentityContext() {
        BrokeredIdentityContext context = new BrokeredIdentityContext("1234");
        context.setContextData(Map.of("state", "5555"));

        String inspected = Util.inspect("context", context);

        Assert.assertEquals("context >>>\n" +
                "\tid: 1234\n" +
                "\tlegacyId: null\n" +
                "\tusername: null\n" +
                "\tmodelUsername: null\n" +
                "\temail: null\n" +
                "\tfirstName: null\n" +
                "\tlastName: null\n" +
                "\tbrokerSessionId: null\n" +
                "\tbrokerUserId: null\n" +
                "\ttoken: null\n" +
                "\tidpConfig: null\n" +
                "\tidp: null\n" +
                "\tcontextData: {state=5555}\n" +
                "\tauthenticationSession: null\n" +
                "context <<<\n", inspected);
    }

    @Test
    public void inspectNull() {
        String inspected = Util.inspect("var", null);
        Assert.assertEquals("var >>>\n" +
                "\tvar = null\n" +
                "var <<<\n", inspected);
    }

    @Test
    public void inspectKeycloakSession() {
        var session = new MockedKeycloakSession();
        var inspected = Util.inspect("session", session);
        Assert.assertEquals("session >>>\n" +
                "session <<<\n", inspected);
    }
}