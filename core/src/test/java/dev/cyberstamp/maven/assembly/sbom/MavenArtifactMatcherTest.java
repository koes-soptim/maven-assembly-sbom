package dev.cyberstamp.maven.assembly.sbom;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MavenArtifactMatcherTest {

    @TempDir
    Path tempDir;

    private static MavenMatch match(String artifactId) {
        return new MavenMatch(ArtifactCoords.of("org.example", artifactId, "1.0"), Identification.remoteCoordinatesLookup());
    }

    @Test
    void chainReturnsFirstMatchAndStopsThere() {
        AtomicInteger thirdCalls = new AtomicInteger();
        MavenArtifactMatcher chain = MavenArtifactMatcher.of(
                file -> Optional.empty(),
                file -> Optional.of(match("second")),
                file -> {
                    thirdCalls.incrementAndGet();
                    return Optional.of(match("third"));
                });

        assertEquals(Optional.of(match("second")), chain.match(new FileEntry("a.jar", "h")));
        assertEquals(0, thirdCalls.get());
    }

    @Test
    void emptyChainMatchesNothing() {
        assertTrue(MavenArtifactMatcher.of().match(new FileEntry("a.jar", "h")).isEmpty());
    }

    @Test
    void cachingMatcherAsksDelegateOncePerContent() throws IOException {
        AtomicInteger calls = new AtomicInteger();
        MavenArtifactMatcher cached = new CachingMatcher(file -> {
            calls.incrementAndGet();
            return Optional.of(match("lib"));
        }, new Sha1Hasher());

        cached.match(entry("a.jar", "same"));
        cached.match(entry("b.jar", "same"));
        cached.match(entry("c.jar", "different"));

        assertEquals(2, calls.get());
    }

    @Test
    void budgetIsSharedAndOnlyConsumedByActualLookups() throws IOException {
        AtomicInteger lookups = new AtomicInteger();
        BudgetedLookup.Budget budget = new BudgetedLookup.Budget(1);
        CoordinatesLookup counting = sha1 -> {
            lookups.incrementAndGet();
            return Optional.empty();
        };
        MavenArtifactMatcher first = new ChecksumLookupMatcher(new BudgetedLookup(counting, budget), new Sha1Hasher());
        MavenArtifactMatcher second = new ChecksumLookupMatcher(new BudgetedLookup(counting, budget), new Sha1Hasher());

        // no source file, so nothing to look up and no budget spent
        first.match(new FileEntry("unpacked.jar", "h"));
        first.match(entry("a.jar", "a"));

        assertThrows(IllegalStateException.class, () -> second.match(entry("b.jar", "b")));
        assertEquals(1, lookups.get());
    }

    private FileEntry entry(String name, String content) throws IOException {
        Path file = tempDir.resolve(name);
        Files.writeString(file, content);
        return new FileEntry(name, "unused", file.toFile());
    }
}
