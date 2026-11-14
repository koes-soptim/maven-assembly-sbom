package dev.cyberstamp.maven.assembly.sbom;

import java.util.Optional;

/**
 * Caps the number of remote lookups a {@link CoordinatesLookup} performs
 * during one SBOM generation run.
 */
final class BudgetedLookup implements CoordinatesLookup {

    private final CoordinatesLookup delegate;
    private final Budget budget;

    BudgetedLookup(CoordinatesLookup delegate, Budget budget) {
        this.delegate = delegate;
        this.budget = budget;
    }

    /**
     * @throws IllegalStateException if the shared budget is exhausted
     */
    @Override
    public Optional<ArtifactCoords> lookup(String sha1Hex) {
        budget.consume();
        return delegate.lookup(sha1Hex);
    }

    /**
     * The lookup budget of one matcher.
     */
    static final class Budget {

        private final String matcherName;
        private final int maxLookups;
        private int used;

        Budget(String matcherName, int maxLookups) {
            this.matcherName = matcherName;
            this.maxLookups = maxLookups;
        }

        void consume() {
            if (used >= maxLookups) {
                throw new IllegalStateException(
                        "<maxLookups> of <" + matcherName + "> (" + maxLookups + ") exhausted; "
                                + "raise <maxLookups>, or narrow <includes>/<excludes> to reduce how many "
                                + "unmatched files are eligible for lookup");
            }
            used++;
        }
    }
}
