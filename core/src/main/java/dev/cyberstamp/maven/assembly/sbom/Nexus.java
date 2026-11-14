package dev.cyberstamp.maven.assembly.sbom;

import java.net.http.HttpClient;

/**
 * Configures lookup against a Nexus Repository Manager 3 instance ({@code <nexus>}), e.g. with
 * {@code <url>https://nexus.example.com/service/rest/v1/search?sha1={sha1}</url>}.
 */
public class Nexus extends ChecksumSearchMatcherConfig {

    private String serverId;

    /**
     * Returns the {@code settings.xml} {@code <server>} id whose credentials
     * are sent as HTTP Basic authentication.
     *
     * @return the server id, or {@code null} for anonymous access
     */
    public String getServerId() {
        return serverId;
    }

    /**
     * Sets the {@code settings.xml} {@code <server>} id whose credentials are
     * sent as HTTP Basic authentication.
     *
     * @param serverId the server id
     */
    public void setServerId(String serverId) {
        this.serverId = serverId;
    }

    @Override
    String serverId() {
        return serverId;
    }

    @Override
    String elementName() {
        return "nexus";
    }

    @Override
    CoordinatesLookup newLookup(HttpClient client, String url, String basicAuthHeader) {
        return new NexusCoordinatesLookup(client, timeout(), url, basicAuthHeader);
    }
}
