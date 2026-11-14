package dev.cyberstamp.maven.assembly.sbom;

import java.util.Objects;

/**
 * A Maven artifact identified by a {@link MavenArtifactMatcher}.
 *
 * @param coords the identified coordinates; never {@code null}
 * @param identification how the coordinates were determined; never {@code null}
 */
record MavenMatch(ArtifactCoords coords, Identification identification) {

    MavenMatch {
        Objects.requireNonNull(coords, "coords");
        Objects.requireNonNull(identification, "identification");
    }
}
