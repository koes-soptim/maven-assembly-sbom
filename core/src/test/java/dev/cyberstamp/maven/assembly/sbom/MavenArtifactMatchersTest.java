package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.sun.net.httpserver.HttpServer;

class MavenArtifactMatchersTest {

    private static final Function<String, ServerCredentials> NO_SERVERS = serverId -> null;
    private static final String NEXUS_HIT = "{\"items\":[{\"group\":\"com.example\",\"name\":\"from-nexus\",\"version\":\"1.0\"}]}";
    private static final String NEXUS_MISS = "{\"items\":[]}";
    private static final String ARTIFACTORY_HIT = "{\"results\":[{\"uri\":\"http://x/api/storage/repo/com/example/from-artifactory/1.0/from-artifactory-1.0.jar\"}]}";

    @TempDir
    Path tempDir;

    private final List<HttpServer> servers = new ArrayList<>();
    private final List<String> authHeaders = new ArrayList<>();

    @AfterEach
    void stopServers() {
        servers.forEach(s -> s.stop(0));
    }

    @Test
    void nothingConfiguredYieldsNoMatcher() {
        assertTrue(MavenArtifactMatchers.create(null, false, NO_SERVERS).isEmpty());
        assertTrue(MavenArtifactMatchers.create(List.of(), false, NO_SERVERS).isEmpty());
    }

    @Test
    void matchersAreTriedInConfiguredOrder() throws IOException {
        AtomicInteger nexusHits = new AtomicInteger();
        AtomicInteger artifactoryHits = new AtomicInteger();
        Artifactory artifactory = artifactory(server("/api/search/checksum", artifactoryHits, ARTIFACTORY_HIT));
        Nexus nexus = nexus(server("/service/rest/v1/search", nexusHits, NEXUS_HIT));

        MavenArtifactMatcher matcher = MavenArtifactMatchers.create(List.of(artifactory, nexus), false, NO_SERVERS)
                .orElseThrow();

        assertEquals("from-artifactory", matcher.match(entry("lib/a.jar", "a")).orElseThrow().coords().artifactId());
        assertEquals(1, artifactoryHits.get());
        assertEquals(0, nexusHits.get(), "the second matcher must not be asked once the first matched");
    }

    @Test
    void laterMatcherIsAskedWhenEarlierHasNoMatch() throws IOException {
        Nexus nexus = nexus(server("/service/rest/v1/search", new AtomicInteger(), NEXUS_MISS));
        Artifactory artifactory = artifactory(server("/api/search/checksum", new AtomicInteger(), ARTIFACTORY_HIT));

        MavenArtifactMatcher matcher = MavenArtifactMatchers.create(List.of(nexus, artifactory), false, NO_SERVERS)
                .orElseThrow();

        assertEquals("from-artifactory", matcher.match(entry("lib/a.jar", "a")).orElseThrow().coords().artifactId());
    }

    @Test
    void includesDefaultToAllJarsAndArePerMatcher() throws IOException {
        AtomicInteger nexusHits = new AtomicInteger();
        Nexus internalOnly = nexus(server("/service/rest/v1/search", nexusHits, NEXUS_HIT));
        internalOnly.setIncludes(List.of("internal/*.jar"));
        AtomicInteger artifactoryHits = new AtomicInteger();
        Artifactory everyJar = artifactory(server("/api/search/checksum", artifactoryHits, ARTIFACTORY_HIT));

        MavenArtifactMatcher matcher = MavenArtifactMatchers.create(List.of(internalOnly, everyJar), false, NO_SERVERS)
                .orElseThrow();

        assertEquals("from-nexus", matcher.match(entry("internal/x.jar", "x")).orElseThrow().coords().artifactId());
        assertEquals("from-artifactory", matcher.match(entry("root.jar", "r")).orElseThrow().coords().artifactId());
        assertTrue(matcher.match(entry("lib/readme.txt", "t")).isEmpty());
        assertEquals(1, nexusHits.get());
        assertEquals(1, artifactoryHits.get());
    }

    @Test
    void serverCredentialsAreSentAsBasicAuth() throws IOException {
        Nexus nexus = nexus(server("/service/rest/v1/search", new AtomicInteger(), NEXUS_HIT));
        nexus.setServerId("my-nexus");
        Function<String, ServerCredentials> servers = Map.of("my-nexus", new ServerCredentials("alice", "s3cr3t"))::get;

        MavenArtifactMatchers.create(List.of(nexus), false, servers).orElseThrow().match(entry("a.jar", "a"));

        assertEquals(List.of(HttpLookupSupport.basicAuthHeader("alice", "s3cr3t")), authHeaders);
    }

    @Test
    void unknownServerIdFallsBackToAnonymousAccess() throws IOException {
        Nexus nexus = nexus(server("/service/rest/v1/search", new AtomicInteger(), NEXUS_HIT));
        nexus.setServerId("missing");

        MavenArtifactMatchers.create(List.of(nexus), false, NO_SERVERS).orElseThrow().match(entry("a.jar", "a"));

        assertEquals(1, authHeaders.size());
        assertNull(authHeaders.get(0));
    }

    @Test
    void remoteMatchersAreSkippedOffline() {
        Nexus nexus = new Nexus();
        nexus.setUrl("http://127.0.0.1:1/search?sha1={sha1}");

        assertTrue(MavenArtifactMatchers.create(List.of(nexus, new Central()), true, NO_SERVERS).isEmpty());
    }

    @Test
    void centralNeedsNoUrl() {
        assertTrue(MavenArtifactMatchers.create(List.of(new Central()), false, NO_SERVERS).isPresent());
    }

    @Test
    void duplicateCentralIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> MavenArtifactMatchers.create(List.of(new Central(), new Central()), false, NO_SERVERS));
        assertTrue(e.getMessage().contains("<central/>"));
    }

    @Test
    void multipleNexusInstancesAreAllowed() {
        Nexus first = new Nexus();
        first.setUrl("http://127.0.0.1:1/a?sha1={sha1}");
        Nexus second = new Nexus();
        second.setUrl("http://127.0.0.1:1/b?sha1={sha1}");

        assertTrue(MavenArtifactMatchers.create(List.of(first, second), false, NO_SERVERS).isPresent());
    }

    @Test
    void missingUrlIsRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> MavenArtifactMatchers.create(List.of(new Artifactory()), false, NO_SERVERS));
        assertTrue(e.getMessage().contains("<artifactory> requires a <url>"));
    }

    @Test
    void urlWithoutPlaceholderIsRejected() {
        Nexus nexus = new Nexus();
        nexus.setUrl("http://nexus.invalid/service/rest/v1/search");

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> MavenArtifactMatchers.create(List.of(nexus), false, NO_SERVERS));
        assertTrue(e.getMessage().contains("{sha1}"));
    }

    @Test
    void invalidIncludesAreRejected() {
        Central central = new Central();
        central.setIncludes(List.of("[unclosed"));

        assertThrows(IllegalArgumentException.class,
                () -> MavenArtifactMatchers.create(List.of(central), false, NO_SERVERS));
    }

    @Test
    void maxLookupsIsPerMatcher() throws IOException {
        Nexus nexus = nexus(server("/service/rest/v1/search", new AtomicInteger(), NEXUS_MISS));
        nexus.setMaxLookups(1);
        Artifactory artifactory = artifactory(server("/api/search/checksum", new AtomicInteger(), ARTIFACTORY_HIT));
        artifactory.setMaxLookups(5);
        MavenArtifactMatcher matcher = MavenArtifactMatchers.create(List.of(nexus, artifactory), false, NO_SERVERS)
                .orElseThrow();

        matcher.match(entry("a.jar", "a"));
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> matcher.match(entry("b.jar", "b")));

        assertTrue(e.getMessage().contains("<nexus>"));
    }

    private HttpServer server(String path, AtomicInteger hits, String body) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(path, exchange -> {
            hits.incrementAndGet();
            authHeaders.add(exchange.getRequestHeaders().getFirst("Authorization"));
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        servers.add(server);
        return server;
    }

    private static Nexus nexus(HttpServer server) {
        Nexus nexus = new Nexus();
        nexus.setUrl("http://127.0.0.1:" + server.getAddress().getPort() + "/service/rest/v1/search?sha1={sha1}");
        return nexus;
    }

    private static Artifactory artifactory(HttpServer server) {
        Artifactory artifactory = new Artifactory();
        artifactory.setUrl("http://127.0.0.1:" + server.getAddress().getPort() + "/api/search/checksum?sha1={sha1}");
        return artifactory;
    }

    private FileEntry entry(String archivePath, String content) throws IOException {
        Path file = tempDir.resolve(archivePath.replace('/', '_'));
        Files.writeString(file, content, StandardCharsets.UTF_8);
        return new FileEntry(archivePath, "unused", file.toFile());
    }
}
