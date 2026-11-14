package dev.cyberstamp.maven.assembly.sbom;

import java.util.Optional;

/**
 * Adapts a SHA-1-keyed {@link CoordinatesLookup} (one remote repository) to a
 * {@link MavenArtifactMatcher}.
 */
final class ChecksumLookupMatcher implements MavenArtifactMatcher {

    private final CoordinatesLookup lookup;
    private final Sha1Hasher hasher;

    ChecksumLookupMatcher(CoordinatesLookup lookup, Sha1Hasher hasher) {
        this.lookup = lookup;
        this.hasher = hasher;
    }

    @Override
    public Optional<MavenMatch> match(FileEntry file) {
        return hasher.sha1(file)
                .flatMap(lookup::lookup)
                .map(coords -> new MavenMatch(coords, Identification.remoteCoordinatesLookup()));
    }
}
