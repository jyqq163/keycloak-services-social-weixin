package org.keycloak.social.weixin;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class JsonHelper {
    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    public static String stringify(Object anything) {
        return gson.toJson(anything);
    }

    public static Object parse(String s) {
        return gson.fromJson(s, Object.class);
    }
}