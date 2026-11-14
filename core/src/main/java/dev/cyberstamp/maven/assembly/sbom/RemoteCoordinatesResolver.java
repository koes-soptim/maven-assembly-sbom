package dev.cyberstamp.maven.assembly.sbom;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds the {@link MavenArtifactMatcher} that identifies otherwise-unmatched
 * archive entries (e.g. jars built with Gradle or Ant, which carry no Maven
 * {@code pom.properties}) by looking up their SHA-1 content hash against one
 * or more remote package repositories.
 *
 * <p>
 * The result is composed of small parts: a {@link PathFilterMatcher} for the
 * include/exclude globs, wrapping a {@link CachingMatcher} that remembers
 * results per SHA-1, wrapping a first-match-wins chain with one
 * {@link ChecksumLookupMatcher} per configured repository. All repository
 * calls share one {@link BudgetedLookup.Budget}.
 * </p>
 */
final class RemoteCoordinatesResolver {

    private static final Logger log = LoggerFactory.getLogger(RemoteCoordinatesResolver.class);

    /**
     * Fallback include pattern used when {@link RemoteArtifactLookup#getIncludes()}
     * is unset, so that enabling the feature alone is enough to try it.
     */
    private static final List<String> DEFAULT_INCLUDES = List.of("*.jar", "**/*.jar");

    private RemoteCoordinatesResolver() {
    }

    /**
     * Builds the matcher from user configuration and already-decrypted
     * repository credentials, or returns empty if the feature is disabled or
     * not usable as configured (no backend, or no valid include glob) — callers
     * should treat an empty result as "feature off".
     *
     * @param config the user configuration, or {@code null}
     * @param nexusUsername decrypted Nexus username, or {@code null} for
     *        anonymous access
     * @param nexusPassword decrypted Nexus password, or {@code null}
     * @param artifactoryUsername decrypted Artifactory username, or
     *        {@code null} for anonymous access
     * @param artifactoryPassword decrypted Artifactory password, or
     *        {@code null}
     * @return the matcher, or empty if disabled/unusable
     */
    static Optional<MavenArtifactMatcher> create(RemoteArtifactLookup config,
            String nexusUsername, String nexusPassword,
            String artifactoryUsername, String artifactoryPassword) {
        if (config == null || !config.isEnabled()) {
            return Optional.empty();
        }
        List<CoordinatesLookup> backends = buildBackends(
                config, nexusUsername, nexusPassword, artifactoryUsername, artifactoryPassword);
        if (backends.isEmpty()) {
            log.warn("remoteMavenCoordinatesLookup is enabled but no backend is configured "
                    + "(central is disabled and neither nexusUrl nor artifactoryUrl is set); "
                    + "remote lookup will not run.");
            return Optional.empty();
        }
        List<String> includes = config.includesOrEmpty();
        if (includes.isEmpty()) {
            includes = DEFAULT_INCLUDES;
            log.info("remoteMavenCoordinatesLookup.includes not configured; defaulting to {}", DEFAULT_INCLUDES);
        }

        Sha1Hasher hasher = new Sha1Hasher();
        BudgetedLookup.Budget budget = new BudgetedLookup.Budget(config.getMaxLookups());
        List<MavenArtifactMatcher> chain = new ArrayList<>(backends.size());
        for (CoordinatesLookup backend : backends) {
            chain.add(new ChecksumLookupMatcher(new BudgetedLookup(backend, budget), hasher));
        }
        MavenArtifactMatcher cached = new CachingMatcher(MavenArtifactMatcher.of(chain), hasher);

        Optional<MavenArtifactMatcher> filtered = PathFilterMatcher.of(cached, includes, config.excludesOrEmpty());
        if (filtered.isEmpty()) {
            log.warn("None of the configured remoteMavenCoordinatesLookup.includes patterns are valid globs; "
                    + "remote lookup will not run.");
        }
        return filtered;
    }

    private static List<CoordinatesLookup> buildBackends(RemoteArtifactLookup config,
            String nexusUsername, String nexusPassword,
            String artifactoryUsername, String artifactoryPassword) {
        Duration timeout = Duration.ofMillis(Math.max(1, config.getTimeoutMillis()));
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .build();
        List<CoordinatesLookup> backends = new ArrayList<>(3);
        if (config.isCentral()) {
            String centralUrl = config.getCentralUrl();
            if (!isSet(centralUrl)) {
                backends.add(new MavenCentralCoordinatesLookup(client, timeout));
            } else if (centralUrl.contains(MavenCentralCoordinatesLookup.PLACEHOLDER)) {
                backends.add(new MavenCentralCoordinatesLookup(client, timeout, centralUrl));
            } else {
                log.warn("centralUrl must be a complete search URL containing a {} placeholder "
                        + "(e.g. {}); Maven Central lookup will not run.",
                        MavenCentralCoordinatesLookup.PLACEHOLDER, MavenCentralCoordinatesLookup.DEFAULT_SEARCH_URL);
            }
        }
        if (isSet(config.getNexusUrl())) {
            if (config.getNexusUrl().contains(NexusCoordinatesLookup.PLACEHOLDER)) {
                String auth = authHeader(nexusUsername, nexusPassword);
                backends.add(new NexusCoordinatesLookup(client, timeout, config.getNexusUrl(), auth));
            } else {
                log.warn("nexusUrl must be a complete search URL containing a {} placeholder "
                        + "(e.g. https://nexus.example.com/service/rest/v1/search?sha1={}); "
                        + "Nexus lookup will not run.", NexusCoordinatesLookup.PLACEHOLDER, NexusCoordinatesLookup.PLACEHOLDER);
            }
        }
        if (isSet(config.getArtifactoryUrl())) {
            if (config.getArtifactoryUrl().contains(ArtifactoryCoordinatesLookup.PLACEHOLDER)) {
                String auth = authHeader(artifactoryUsername, artifactoryPassword);
                backends.add(new ArtifactoryCoordinatesLookup(client, timeout, config.getArtifactoryUrl(), auth));
            } else {
                log.warn("artifactoryUrl must be a complete search URL containing a {} placeholder "
                        + "(e.g. https://artifactory.example.com/artifactory/api/search/checksum?sha1={}); "
                        + "Artifactory lookup will not run.",
                        ArtifactoryCoordinatesLookup.PLACEHOLDER, ArtifactoryCoordinatesLookup.PLACEHOLDER);
            }
        }
        return backends;
    }

    private static boolean isSet(String value) {
        return value != null && !value.isBlank();
    }

    private static String authHeader(String username, String password) {
        if (!isSet(username) || password == null) {
            return null;
        }
        return HttpLookupSupport.basicAuthHeader(username, password);
    }
}
