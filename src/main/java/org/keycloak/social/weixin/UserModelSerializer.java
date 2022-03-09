package org.keycloak.social.weixin;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import org.keycloak.models.UserModel;

import java.lang.reflect.Type;
import java.util.Objects;

public class UserModelSerializer implements JsonSerializer<UserModel> {
    @Override
    public JsonElement serialize(UserModel userModel, Type type, JsonSerializationContext jsonSerializationContext) {
        var jsonObject = new JsonObject();

        jsonObject.addProperty("username", userModel.getUsername());
        jsonObject.addProperty("id", userModel.getId());
        jsonObject.addProperty("email", userModel.getEmail());
        jsonObject.addProperty("enabled", userModel.isEnabled());
        jsonObject.addProperty("firstName", userModel.getFirstName());
        jsonObject.addProperty("lastName", userModel.getLastName());
        jsonObject.addProperty("createdTimestamp", userModel.getCreatedTimestamp());
        jsonObject.addProperty("federationLink", userModel.getFederationLink());
        jsonObject.addProperty("serviceAccountClientLink", userModel.getServiceAccountClientLink());
        jsonObject.addProperty("groupsCount", userModel.getGroupsCount());
        jsonObject.addProperty("attributes", Objects.requireNonNullElse(userModel.getAttributes(), "").toString());

        return jsonObject;
    }
}
