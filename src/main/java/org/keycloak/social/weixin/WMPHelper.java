package org.keycloak.social.weixin;

import org.keycloak.broker.provider.util.IdentityBrokerState;

public class WMPHelper {
    public static String createStateForWMP(String clientId, String tabId) {
        return IdentityBrokerState.decoded("wmp", clientId, tabId).getEncoded();
    }
}
