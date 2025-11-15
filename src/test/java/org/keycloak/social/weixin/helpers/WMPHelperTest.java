package org.keycloak.social.weixin.helpers;

import org.junit.jupiter.api.Test;
import org.keycloak.social.weixin.helpers.WMPHelper;

import static org.junit.jupiter.api.Assertions.*;

class WMPHelperTest {

    @Test
    void createStateForWMP() {
        assertEquals("wmp.tab.client.clientData", WMPHelper.createStateForWMP("client", "tab","clientData"));
    }
}
