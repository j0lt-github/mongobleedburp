package com.j0lt.mongobleed;

import java.util.Collections;
import java.util.List;
import java.util.Set;

public class ScanResult {
    private final List<LeakItem> leaks;
    private final int totalBytes;
    private final Set<String> keywordHits;
    private final int probesTried;
    private final long durationMs;
    private final boolean cancelled;

    public ScanResult(
            List<LeakItem> leaks,
            int totalBytes,
            Set<String> keywordHits,
            int probesTried,
            long durationMs,
            boolean cancelled
    ) {
        this.leaks = leaks == null ? Collections.emptyList() : Collections.unmodifiableList(leaks);
        this.totalBytes = totalBytes;
        this.keywordHits = keywordHits == null ? Collections.emptySet() : Collections.unmodifiableSet(keywordHits);
        this.probesTried = probesTried;
        this.durationMs = durationMs;
        this.cancelled = cancelled;
    }

    public List<LeakItem> getLeaks() {
        return leaks;
    }

    public int getTotalBytes() {
        return totalBytes;
    }

    public Set<String> getKeywordHits() {
        return keywordHits;
    }

    public int getProbesTried() {
        return probesTried;
    }

    public long getDurationMs() {
        return durationMs;
    }

    public boolean isCancelled() {
        return cancelled;
    }
}
