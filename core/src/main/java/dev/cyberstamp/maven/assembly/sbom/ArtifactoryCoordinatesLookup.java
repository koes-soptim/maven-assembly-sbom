package dev.cyberstamp.maven.assembly.sbom;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Looks up Maven coordinates by SHA-1 against an internal JFrog Artifactory
 * instance, using its checksum search API.
 *
 * <p>
 * Unlike Maven Central and Nexus, Artifactory's checksum search does not
 * return structured group/artifact/version fields; it returns the storage
 * {@code uri} of the matching item instead. Coordinates are recovered from
 * that path by assuming the standard Maven2 repository layout:
 * {@code .../api/storage/<repoKey>/<groupPath>/<artifactId>/<version>/<file>}.
 * </p>
 *
 * <p>
 * The classifier and extension are read, on a best-effort basis, from a file
 * name of the form {@code <artifactId>-<version>[-<classifier>].<extension>},
 * including timestamped snapshots
 * ({@code <artifactId>-1.0-20240101.123456-1[-<classifier>].<extension>}).
 * A classifier ends at its first dot, so classifiers that themselves contain a
 * dot are misread. If the file name does not follow this form, the
 * coordinates are reported without classifier.
 * </p>
 *
 * <p>
 * The configured URL must be a complete search request containing a literal
 * {@code {sha1}} placeholder for the content hash (see {@link #PLACEHOLDER}),
 * e.g.
 * {@code https://artifactory.example.com/artifactory/api/search/checksum?sha1={sha1}}.
 * This is deliberately not derived from a bare base URL: the REST path and
 * any extra filters (e.g. Artifactory's {@code repos} parameter) are under
 * JFrog's control, and hardcoding them here could go stale. Requiring the
 * full URL means an Artifactory-side API change only needs a config update,
 * not a new plugin release.
 * </p>
 */
final class ArtifactoryCoordinatesLookup implements CoordinatesLookup {

    /**
     * Literal marker substituted with the content hash in the configured
     * search URL.
     */
    static final String PLACEHOLDER = "{sha1}";

    /**
     * The {@code yyyyMMdd.HHmmss-buildNumber} part of a timestamped snapshot file name.
     */
    private static final Pattern SNAPSHOT_TIMESTAMP = Pattern.compile("\\d{8}\\.\\d{6}-\\d+");

    private final HttpClient client;
    private final Duration timeout;
    private final String searchUrlTemplate;
    private final HttpLookupSupport.FailureLog failures = new HttpLookupSupport.FailureLog("Artifactory");
    private final String basicAuthHeader;

    ArtifactoryCoordinatesLookup(HttpClient client, Duration timeout, String searchUrlTemplate, String basicAuthHeader) {
        this.client = client;
        this.timeout = timeout;
        this.searchUrlTemplate = searchUrlTemplate;
        this.basicAuthHeader = basicAuthHeader;
    }

    @Override
    public Optional<ArtifactCoords> lookup(String sha1Hex) {
        URI uri = URI.create(searchUrlTemplate.replace(PLACEHOLDER, sha1Hex));
        return HttpLookupSupport.get(client, uri, timeout, basicAuthHeader, failures)
                .flatMap(body -> JsonLookupSupport.firstArrayObject(body, "results"))
                .flatMap(result -> JsonLookupSupport.stringField(result, "uri"))
                .flatMap(ArtifactoryCoordinatesLookup::toCoords);
    }

    /**
     * Recovers {@code groupId:artifactId:version} from a storage {@code uri}
     * following the standard Maven2 layout, anchored at the {@code storage}
     * path segment that precedes the repository key.
     *
     * @return the coordinates, or empty if the path does not follow the
     *         expected shape (e.g. a non-Maven-layout repository)
     */
    private static Optional<ArtifactCoords> toCoords(String uri) {
        String path = URI.create(uri).getPath();
        if (path == null) {
            return Optional.empty();
        }
        List<String> segments = new ArrayList<>();
        for (String segment : path.split("/")) {
            if (!segment.isEmpty()) {
                segments.add(segment);
            }
        }
        int storageIdx = segments.lastIndexOf("storage");
        if (storageIdx < 0) {
            return Optional.empty();
        }
        // segments after "storage": [repoKey, g1, g2, ..., artifactId, version, file]
        List<String> repoRelative = segments.subList(storageIdx + 1, segments.size());
        if (repoRelative.size() < 4) {
            return Optional.empty();
        }
        int size = repoRelative.size();
        String version = repoRelative.get(size - 2);
        String artifactId = repoRelative.get(size - 3);
        List<String> groupPath = repoRelative.subList(1, size - 3);
        if (groupPath.isEmpty()) {
            return Optional.empty();
        }
        String groupId = String.join(".", groupPath);
        return Optional.of(fromFileName(groupId, artifactId, version, repoRelative.get(size - 1)));
    }

    /**
     * Derives the classifier and extension from a Maven2-layout file name,
     * falling back to coordinates without classifier if the name does not
     * start with {@code <artifactId>-<version>}.
     */
    static ArtifactCoords fromFileName(String groupId, String artifactId, String version, String fileName) {
        ArtifactCoords plain = ArtifactCoords.of(groupId, artifactId, version);
        String prefix = artifactId + "-";
        if (!fileName.startsWith(prefix)) {
            return plain;
        }
        String rest = fileName.substring(prefix.length());
        int versionLength = fileVersionLength(rest, version);
        if (versionLength < 0) {
            return plain;
        }
        String tail = rest.substring(versionLength);
        if (tail.startsWith(".") && tail.length() > 1) {
            return new ArtifactCoords(groupId, artifactId, version, tail.substring(1), null);
        }
        int dot = tail.indexOf('.');
        if (tail.startsWith("-") && dot > 1 && dot < tail.length() - 1) {
            return new ArtifactCoords(groupId, artifactId, version, tail.substring(dot + 1), tail.substring(1, dot));
        }
        return plain;
    }

    /**
     * Returns the length of the version as it appears at the start of
     * {@code rest}: the version itself, or for a snapshot either
     * {@code X-SNAPSHOT} or its timestamped form; {@code -1} if neither.
     */
    private static int fileVersionLength(String rest, String version) {
        if (rest.startsWith(version)) {
            return version.length();
        }
        String snapshotSuffix = "SNAPSHOT";
        if (!version.endsWith("-" + snapshotSuffix)) {
            return -1;
        }
        String base = version.substring(0, version.length() - snapshotSuffix.length());
        if (!rest.startsWith(base)) {
            return -1;
        }
        Matcher timestamp = SNAPSHOT_TIMESTAMP.matcher(rest).region(base.length(), rest.length());
        return timestamp.lookingAt() ? timestamp.end() : -1;
    }
}
