package com.j0lt.mongobleed;

import java.nio.charset.StandardCharsets;

public final class FormatUtils {
    private FormatUtils() {
    }

    public static String preview(byte[] data, int maxLen) {
        if (data == null || data.length == 0) {
            return "";
        }
        int len = Math.min(data.length, maxLen);
        StringBuilder sb = new StringBuilder(len + 3);
        for (int i = 0; i < len; i++) {
            int b = data[i] & 0xFF;
            if (b >= 32 && b <= 126) {
                sb.append((char) b);
            } else {
                sb.append('.');
            }
        }
        if (data.length > maxLen) {
            sb.append("...");
        }
        return sb.toString();
    }

    public static String hexAsciiDump(byte[] data, int width) {
        if (data == null || data.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        int offset = 0;
        while (offset < data.length) {
            int lineLen = Math.min(width, data.length - offset);
            sb.append(String.format("%04x  ", offset));
            for (int i = 0; i < width; i++) {
                if (i < lineLen) {
                    sb.append(String.format("%02x ", data[offset + i] & 0xFF));
                } else {
                    sb.append("   ");
                }
            }
            sb.append(" |");
            for (int i = 0; i < lineLen; i++) {
                int b = data[offset + i] & 0xFF;
                sb.append(b >= 32 && b <= 126 ? (char) b : '.');
            }
            sb.append("|\n");
            offset += lineLen;
        }
        return sb.toString();
    }

    public static String safeUtf8(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        String text = new String(data, StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c >= 32 && c != 127) {
                sb.append(c);
            } else {
                sb.append('.');
            }
        }
        return sb.toString();
    }
}
