package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

class PathFilterMatcherTest {

    private static final MavenMatch MATCH = new MavenMatch(
            ArtifactCoords.of("org.example", "lib", "1.0"), Identification.remoteCoordinatesLookup());

    private static final MavenArtifactMatcher ALWAYS = file -> Optional.of(MATCH);

    @Test
    void honorsIncludesAndExcludes() {
        MavenArtifactMatcher filter = PathFilterMatcher.of(ALWAYS,
                List.of("**/*.jar"), List.of("**/test-*.jar")).orElseThrow();

        assertTrue(filter.match(new FileEntry("lib/foo.jar", "h")).isPresent());
        assertTrue(filter.match(new FileEntry("lib/test-foo.jar", "h")).isEmpty());
        assertTrue(filter.match(new FileEntry("lib/foo.txt", "h")).isEmpty());
    }

    @Test
    void doubleStarGlobRequiresADirectory() {
        MavenArtifactMatcher filter = PathFilterMatcher.of(ALWAYS, List.of("**/*.jar"), List.of()).orElseThrow();

        assertTrue(filter.match(new FileEntry("foo.jar", "h")).isEmpty());
    }

    @Test
    void invalidGlobsAreSkipped() {
        assertTrue(PathFilterMatcher.of(ALWAYS, List.of("[unclosed"), List.of()).isEmpty());
        assertTrue(PathFilterMatcher.of(ALWAYS, List.of("[unclosed", "*.jar"), List.of()).isPresent());
    }
}
