package dev.cyberstamp.maven.assembly.sbom;

import java.net.http.HttpClient;
import java.time.Duration;

/**
 * Configuration of a matcher that looks up a file's SHA-1 through a remote
 * repository's search API.
 */
public abstract class ChecksumSearchMatcherConfig extends MavenArtifactMatcherConfig {

    /**
     * Literal marker substituted with the content hash in the search URL.
     */
    static final String PLACEHOLDER = "{sha1}";

    private String url;
    private int timeoutMillis = 3000;
    private int maxLookups = 200;

    /**
     * Returns the complete search URL with a literal {@code {sha1}} in place
     * of the content hash.
     *
     * @return the search URL, or {@code null} if unset
     */
    public String getUrl() {
        return url;
    }

    /**
     * Sets the complete search URL, with a literal {@code {sha1}} in place of
     * the content hash. The rest of the URL is used exactly as given, so
     * repository-specific query parameters can be added.
     *
     * @param url the search URL
     */
    public void setUrl(String url) {
        this.url = url;
    }

    /**
     * Returns the per-request timeout, in milliseconds.
     *
     * @return the timeout in milliseconds
     */
    public int getTimeoutMillis() {
        return timeoutMillis;
    }

    /**
     * Sets the per-request timeout, in milliseconds.
     *
     * @param timeoutMillis the timeout in milliseconds
     */
    public void setTimeoutMillis(int timeoutMillis) {
        this.timeoutMillis = timeoutMillis;
    }

    /**
     * Returns the maximum number of lookups this matcher performs in one run.
     *
     * @return the maximum number of lookups
     */
    public int getMaxLookups() {
        return maxLookups;
    }

    /**
     * Sets the maximum number of lookups this matcher performs in one run.
     * Exceeding it fails the build rather than silently leaving files
     * unidentified.
     *
     * @param maxLookups the maximum number of lookups
     */
    public void setMaxLookups(int maxLookups) {
        this.maxLookups = maxLookups;
    }

    Duration timeout() {
        return Duration.ofMillis(Math.max(1, timeoutMillis));
    }

    /**
     * Returns the URL used when none is configured, or {@code null} if a URL
     * is required.
     */
    String defaultUrl() {
        return null;
    }

    /**
     * Returns the {@code settings.xml} server id whose credentials are sent,
     * or {@code null} for anonymous access.
     */
    String serverId() {
        return null;
    }

    abstract CoordinatesLookup newLookup(HttpClient client, String url, String basicAuthHeader);

    @Override
    boolean isRemote() {
        return true;
    }

    @Override
    MavenArtifactMatcher create(MatcherContext context) {
        String effectiveUrl = url != null && !url.isBlank() ? url.trim() : defaultUrl();
        if (effectiveUrl == null) {
            throw new IllegalArgumentException("<" + elementName() + "> requires a <url>");
        }
        if (!effectiveUrl.contains(PLACEHOLDER)) {
            throw new IllegalArgumentException("<" + elementName() + "> <url> must contain a " + PLACEHOLDER
                    + " placeholder for the content hash: " + effectiveUrl);
        }
        String authHeader = context.basicAuthHeader(serverId());
        CoordinatesLookup lookup = new BudgetedLookup(newLookup(context.httpClient(), effectiveUrl, authHeader),
                new BudgetedLookup.Budget(elementName(), maxLookups));
        MavenArtifactMatcher matcher = new CachingMatcher(
                new ChecksumLookupMatcher(lookup, context.hasher()), context.hasher());
        return PathFilterMatcher.of(matcher, effectiveIncludes(), effectiveExcludes())
                .orElseThrow(() -> new IllegalArgumentException(
                        "None of the <includes> of <" + elementName() + "> is a valid glob pattern"));
    }
}
