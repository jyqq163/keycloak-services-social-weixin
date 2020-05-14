package org.keycloak.social.weixin.mock;

import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.ResteasyAsynchronousContext;
import org.jboss.resteasy.spi.ResteasyUriInfo;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import java.io.InputStream;
import java.net.URI;
import java.util.Enumeration;

public class MockedHttpRequest implements HttpRequest {
    private MockedHttpHeaders httpHeaders;

    public MockedHttpRequest() {
        this.httpHeaders = new MockedHttpHeaders();
    }

    @Override
    public HttpHeaders getHttpHeaders() {
        return this.httpHeaders;
    }

    @Override
    public MultivaluedMap<String, String> getMutableHeaders() {
        return null;
    }

    @Override
    public InputStream getInputStream() {
        return null;
    }

    @Override
    public void setInputStream(InputStream inputStream) {

    }

    @Override
    public ResteasyUriInfo getUri() {
        return null;
    }

    @Override
    public String getHttpMethod() {
        return null;
    }

    @Override
    public void setHttpMethod(String s) {

    }

    @Override
    public void setRequestUri(URI uri) throws IllegalStateException {

    }

    @Override
    public void setRequestUri(URI uri, URI uri1) throws IllegalStateException {

    }

    @Override
    public MultivaluedMap<String, String> getFormParameters() {
        return null;
    }

    @Override
    public MultivaluedMap<String, String> getDecodedFormParameters() {
        return null;
    }

    @Override
    public Object getAttribute(String s) {
        return null;
    }

    @Override
    public void setAttribute(String s, Object o) {

    }

    @Override
    public void removeAttribute(String s) {

    }

    @Override
    public Enumeration<String> getAttributeNames() {
        return null;
    }

    @Override
    public ResteasyAsynchronousContext getAsyncContext() {
        return null;
    }

    @Override
    public boolean isInitial() {
        return false;
    }

    @Override
    public void forward(String s) {

    }

    @Override
    public boolean wasForwarded() {
        return false;
    }
}
