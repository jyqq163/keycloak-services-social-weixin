package org.keycloak.social.weixin.helpers;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.keycloak.models.UserModel;
import org.keycloak.social.weixin.UserModelSerializer;
import org.keycloak.social.weixin.WMPUserSessionModel;
import org.keycloak.social.weixin.WMPUserSessionModelSerializer;

import java.lang.reflect.Type;

public class JsonHelper {
    private static final Gson gson =
            new GsonBuilder().registerTypeAdapter(UserModel.class, new UserModelSerializer()).registerTypeAdapter(WMPUserSessionModel.class, new WMPUserSessionModelSerializer()).enableComplexMapKeySerialization().serializeNulls().setPrettyPrinting().create();

    public static String stringify(Object anything) {
        return gson.toJson(anything);
    }

    public static String stringify(Object anything, Type type) {
        return gson.toJson(anything, type);
    }

    public static Object parse(String s) {
        return gson.fromJson(s, Object.class);
    }
}
