package dev.cyberstamp.maven.assembly.sbom;

import java.net.http.HttpClient;

/**
 * Configures lookup against the public Maven Central search API
 * ({@code <central/>}). Needs no configuration; {@code url} can point at a
 * mirror of the search API.
 */
public class Central extends ChecksumSearchMatcherConfig {

    @Override
    String elementName() {
        return "central";
    }

    @Override
    String defaultUrl() {
        return MavenCentralCoordinatesLookup.DEFAULT_SEARCH_URL;
    }

    @Override
    CoordinatesLookup newLookup(HttpClient client, String url, String basicAuthHeader) {
        return new MavenCentralCoordinatesLookup(client, timeout(), url);
    }
}
