package org.keycloak.social.weixin.helpers;

import lombok.SneakyThrows;

import java.security.MessageDigest;
import java.util.Arrays;

public class WechatMpHelper {
    /**
     * 判断是否是微信公众号消息
     * <p>
     * 验证 URL Echostr 算法：
     * 1. 将 Token （用户在微信后台配置的值），
     * 时间戳（微信请求 URL 时传过来的 timestamp 值），
     * nonce（微信请求 URL 时传过来的 nonce 值）按照字母顺序排列；
     * 2. 排列好后拼成一个字符串；
     * 3. 通过 sha1 算法转换此字符串后的结果如果正常就是 echostr 的值。
     *
     * @return
     */
    @SneakyThrows
    public static boolean isWechatMpMessage(String signature, String timestamp, String nonce) {
        var sortedArr = Arrays.stream(new String[]{"uni-heart", timestamp, nonce}).sorted().toArray();
        StringBuilder content = new StringBuilder();
        for (var item : sortedArr) {
            content.append(item);
        }

        var hash = MessageDigest.getInstance("SHA-1");
        hash.update(content.toString().getBytes());
        var hashed = hash.digest();
        var hexDigest = new StringBuilder();
        for (byte hashByte : hashed) {
            hexDigest.append(String.format("%02x", hashByte));
        }

        var upperCase = hexDigest.toString().toUpperCase();

        return upperCase.equals(signature.toUpperCase());
    }
}
