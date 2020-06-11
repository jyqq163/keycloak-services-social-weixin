package org.keycloak.social.weixin;

import java.lang.reflect.Field;

public class Util {
    public static String inspect(String varName, Object thing) {
        StringBuilder sb = new StringBuilder();

        sb.append(varName).append(" >>>").append("\n");
        for (Field field : thing.getClass().getDeclaredFields()) {
            field.setAccessible(true);
            String name = field.getName();
            Object value = null;
            try {
                value = field.get(thing);
            } catch (IllegalAccessException e) {
                e.printStackTrace();
            }
            sb.append("\t").append(name).append(": ").append(value).append("\n");
        }
        sb.append(varName).append(" <<<").append("\n");

        return sb.toString();
    }
}
