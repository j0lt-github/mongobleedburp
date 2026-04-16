package com.j0lt.mongobleed;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;

public final class TempLeakStore implements Closeable {
    private final Path path;
    private final RandomAccessFile file;
    private final Object lock = new Object();
    private final AtomicBoolean closed = new AtomicBoolean(false);

    private TempLeakStore(Path path, RandomAccessFile file) {
        this.path = path;
        this.file = file;
    }

    public static TempLeakStore create() throws IOException {
        Path path = Files.createTempFile("mongobleed-output-", ".tmp");
        File temp = path.toFile();
        temp.deleteOnExit();
        RandomAccessFile raf = new RandomAccessFile(temp, "rw");
        return new TempLeakStore(path, raf);
    }

    public long append(byte[] data) throws IOException {
        if (data == null) {
            data = new byte[0];
        }
        synchronized (lock) {
            ensureOpen();
            long recordOffset = file.length();
            file.seek(recordOffset);
            file.writeInt(data.length);
            file.write(data);
            return recordOffset;
        }
    }

    /** Maximum single record size (16 MB). Prevents OOM from corrupt records. */
    private static final int MAX_RECORD_BYTES = 16 * 1024 * 1024;

    public byte[] read(long recordOffset) throws IOException {
        synchronized (lock) {
            ensureOpen();
            file.seek(recordOffset);
            int length = file.readInt();
            if (length < 0 || length > MAX_RECORD_BYTES) {
                throw new IOException("Corrupt leak record length: " + length);
            }
            byte[] data = new byte[length];
            file.readFully(data);
            return data;
        }
    }

    @Override
    public void close() throws IOException {
        if (closed.compareAndSet(false, true)) {
            synchronized (lock) {
                file.close();
            }
        }
    }

    public void deleteQuietly() {
        try {
            close();
        } catch (IOException ignored) {
        }
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
        }
    }

    private void ensureOpen() throws IOException {
        if (closed.get()) {
            throw new IOException("Temporary leak store is closed");
        }
    }
}
