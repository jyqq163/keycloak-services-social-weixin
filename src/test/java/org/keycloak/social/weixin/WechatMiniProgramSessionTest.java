package org.keycloak.social.weixin;

import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class WechatMiniProgramSessionTest {

    Stream<String> getRequiredActionsStream(AuthenticatedWMPSession session) {
        Set<String> value = session.getRequiredActions();
        return value != null ? value.stream() : Stream.empty();
    }

    @Test
    void getRequiredActionsEmpty() {
        var sut = new AuthenticatedWMPSession(null, null, null);

        var firstAction = getRequiredActionsStream(sut).findFirst();
        assertFalse(firstAction.isPresent());
    }
}