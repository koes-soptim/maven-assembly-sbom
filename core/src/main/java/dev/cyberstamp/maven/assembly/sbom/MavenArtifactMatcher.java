package dev.cyberstamp.maven.assembly.sbom;

import java.util.Optional;

/**
 * Identifies an archive entry that no built-in technique could match as a
 * Maven artifact, e.g. by looking up its content hash in a remote repository.
 */
interface MavenArtifactMatcher {

    /**
     * Attempts to identify the given file entry.
     *
     * <p>
     * Implementations must not throw for ordinary "no match" or lookup
     * failures; they report those as an empty result.
     * </p>
     *
     * @param file the unmatched archive entry
     * @return the match, or {@link Optional#empty()} if the entry could not be
     *         identified
     */
    Optional<MavenMatch> match(FileEntry file);
}
