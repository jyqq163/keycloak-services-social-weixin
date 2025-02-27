package org.keycloak.social.weixin;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import org.keycloak.models.UserModel;
import org.keycloak.social.weixin.helpers.JsonHelper;

import java.lang.reflect.Type;
import java.util.Objects;

public class WMPUserSessionModelSerializer implements JsonSerializer<WMPUserSessionModel> {
    @Override
    public JsonElement serialize(WMPUserSessionModel wmpUserSessionModel, Type type, JsonSerializationContext jsonSerializationContext) {
        var jsonObject = new JsonObject();
        jsonObject.addProperty("id", wmpUserSessionModel.getId());
        jsonObject.addProperty("realm", Objects.requireNonNullElse(wmpUserSessionModel.getRealm(), "").toString());
        jsonObject.addProperty("brokerSessionId", wmpUserSessionModel.getBrokerSessionId());
        jsonObject.addProperty("brokerUserId", wmpUserSessionModel.getBrokerUserId());
        jsonObject.addProperty("lastSessionRefresh", wmpUserSessionModel.getLastSessionRefresh());
        jsonObject.addProperty("authMethod", wmpUserSessionModel.getAuthMethod());
        jsonObject.addProperty("ipAddress", wmpUserSessionModel.getIpAddress());
        jsonObject.addProperty("user", JsonHelper.stringify(wmpUserSessionModel.getUser(), UserModel.class));
        jsonObject.addProperty("loginUserName", wmpUserSessionModel.getLoginUsername());
        jsonObject.addProperty("started", wmpUserSessionModel.getStarted());
        jsonObject.addProperty("notes", JsonHelper.stringify(wmpUserSessionModel.getNotes()));
        jsonObject.addProperty("authenticatedClientSessions",
                JsonHelper.stringify(wmpUserSessionModel.getAuthenticatedClientSessions()));
        jsonObject.addProperty("state", JsonHelper.stringify(wmpUserSessionModel.getState()));

        return jsonObject;
    }
}
