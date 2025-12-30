package com.j0lt.mongobleed;

public class ScanConfig {
    public final String host;
    public final int port;
    public final int minOffset;
    public final int maxOffset;
    public final int step;
    public final int bufferPad;
    public final int timeoutMs;
    public final int maxLeaks;
    public final int maxTotalBytes;
    public final int maxResponseBytes;
    public final int minLeakLength;
    public final boolean stopOnFirstLeak;
    public final int maxProbes;

    public ScanConfig(
            String host,
            int port,
            int minOffset,
            int maxOffset,
            int step,
            int bufferPad,
            int timeoutMs,
            int maxLeaks,
            int maxTotalBytes,
            int maxResponseBytes,
            int minLeakLength,
            boolean stopOnFirstLeak,
            int maxProbes
    ) {
        this.host = host;
        this.port = port;
        this.minOffset = minOffset;
        this.maxOffset = maxOffset;
        this.step = step;
        this.bufferPad = bufferPad;
        this.timeoutMs = timeoutMs;
        this.maxLeaks = maxLeaks;
        this.maxTotalBytes = maxTotalBytes;
        this.maxResponseBytes = maxResponseBytes;
        this.minLeakLength = minLeakLength;
        this.stopOnFirstLeak = stopOnFirstLeak;
        this.maxProbes = maxProbes;
    }
}
