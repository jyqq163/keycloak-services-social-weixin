package org.keycloak.social.weixin;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class WMPHelperTest {

    @Test
    void createStateForWMP() {
        assertEquals("wmp.tab.client", WMPHelper.createStateForWMP("client", "tab"));
    }
}