package org.keycloak.social.weixin.mock;

import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;

import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class MockedHttpHeaders implements HttpHeaders {
    @Override
    public List<String> getRequestHeader(String s) {
        return null;
    }

    @Override
    public String getHeaderString(String s) {
        return s;
    }

    @Override
    public MultivaluedMap<String, String> getRequestHeaders() {
        return null;
    }

    @Override
    public List<MediaType> getAcceptableMediaTypes() {
        return null;
    }

    @Override
    public List<Locale> getAcceptableLanguages() {
        return null;
    }

    @Override
    public MediaType getMediaType() {
        return null;
    }

    @Override
    public Locale getLanguage() {
        return null;
    }

    @Override
    public Map<String, Cookie> getCookies() {
        return null;
    }

    @Override
    public Date getDate() {
        return null;
    }

    @Override
    public int getLength() {
        return 0;
    }
}
