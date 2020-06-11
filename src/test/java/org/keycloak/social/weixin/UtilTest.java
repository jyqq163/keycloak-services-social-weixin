package org.keycloak.social.weixin;

import org.junit.Assert;
import org.junit.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;

public class UtilTest {
    @Test
    public void inspectBrokeredIdentityContext() {
        BrokeredIdentityContext context = new BrokeredIdentityContext("1234");

        String inspected = Util.inspect("context", context);

        Assert.assertEquals("context >>>\n" +
                "\tid: 1234\n" +
                "\tusername: null\n" +
                "\tmodelUsername: null\n" +
                "\temail: null\n" +
                "\tfirstName: null\n" +
                "\tlastName: null\n" +
                "\tbrokerSessionId: null\n" +
                "\tbrokerUserId: null\n" +
                "\tcode: null\n" +
                "\ttoken: null\n" +
                "\tidpConfig: null\n" +
                "\tidp: null\n" +
                "\tcontextData: {}\n" +
                "\tauthenticationSession: null\n" +
                "context <<<\n", inspected);
    }
}