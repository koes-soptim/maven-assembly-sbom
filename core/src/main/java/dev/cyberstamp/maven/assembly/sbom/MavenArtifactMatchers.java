package dev.cyberstamp.maven.assembly.sbom;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds the {@link MavenArtifactMatcher} described by a
 * {@code <mavenArtifactMatchers>} configuration.
 */
final class MavenArtifactMatchers {

    private static final Logger log = LoggerFactory.getLogger(MavenArtifactMatchers.class);

    private MavenArtifactMatchers() {
    }

    /**
     * Builds a first-match-wins chain of the configured matchers, in
     * configuration order. Remote matchers are skipped in offline mode.
     *
     * @param configs the configured matchers, or {@code null}
     * @param offline whether Maven runs in offline mode
     * @param credentials resolves a {@code settings.xml} server id to its
     *        decrypted credentials, or {@code null} if there is no such server
     * @return the matcher, or empty if nothing is configured (or everything
     *         configured was skipped)
     * @throws IllegalArgumentException if the configuration is invalid
     */
    static Optional<MavenArtifactMatcher> create(List<? extends MavenArtifactMatcherConfig> configs, boolean offline,
            Function<String, ServerCredentials> credentials) {
        if (configs == null || configs.isEmpty()) {
            return Optional.empty();
        }
        if (configs.stream().filter(Central.class::isInstance).count() > 1) {
            throw new IllegalArgumentException("<central/> may only be configured once in <mavenArtifactMatchers>");
        }
        List<MavenArtifactMatcherConfig> active = new ArrayList<>(configs.size());
        for (MavenArtifactMatcherConfig config : configs) {
            if (offline && config.isRemote()) {
                log.warn("Maven is running in offline mode; skipping <{}>, so files only identifiable "
                        + "through it remain file components", config.elementName());
            } else {
                active.add(config);
            }
        }
        if (active.isEmpty()) {
            return Optional.empty();
        }

        MatcherContext context = new MatcherContext(newHttpClient(active), new Sha1Hasher(), credentials);
        List<MavenArtifactMatcher> matchers = new ArrayList<>(active.size());
        try {
            for (MavenArtifactMatcherConfig config : active) {
                matchers.add(config.create(context));
            }
        } catch (RuntimeException e) {
            MavenArtifactMatcher.of(matchers).close();
            throw e;
        }
        return Optional.of(MavenArtifactMatcher.of(matchers));
    }

    /**
     * Creates the HTTP client shared by all remote matchers. Its connect
     * timeout is the longest configured per-request timeout; each matcher
     * still applies its own timeout to its requests.
     */
    private static HttpClient newHttpClient(List<MavenArtifactMatcherConfig> configs) {
        Duration connectTimeout = configs.stream()
                .filter(ChecksumSearchMatcherConfig.class::isInstance)
                .map(c -> ((ChecksumSearchMatcherConfig) c).timeout())
                .max(Duration::compareTo)
                .orElse(Duration.ofSeconds(3));
        return HttpClient.newBuilder().connectTimeout(connectTimeout).build();
    }
}
