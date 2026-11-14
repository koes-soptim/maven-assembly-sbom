package dev.cyberstamp.maven.assembly.sbom;

import java.util.List;
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

    /**
     * Returns a matcher that offers each entry to the given matchers in order;
     * the first match wins.
     *
     * @param matchers the matchers, in priority order
     * @return the combined matcher
     */
    static MavenArtifactMatcher of(MavenArtifactMatcher... matchers) {
        return of(List.of(matchers));
    }

    /**
     * Returns a matcher that offers each entry to the given matchers in order;
     * the first match wins.
     *
     * @param matchers the matchers, in priority order
     * @return the combined matcher
     */
    static MavenArtifactMatcher of(List<? extends MavenArtifactMatcher> matchers) {
        List<MavenArtifactMatcher> chain = List.copyOf(matchers);
        return file -> {
            for (MavenArtifactMatcher matcher : chain) {
                Optional<MavenMatch> match = matcher.match(file);
                if (match.isPresent()) {
                    return match;
                }
            }
            return Optional.empty();
        };
    }
}
