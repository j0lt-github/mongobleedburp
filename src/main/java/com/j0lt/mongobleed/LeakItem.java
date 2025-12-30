package com.j0lt.mongobleed;

import java.util.Arrays;

public class LeakItem {
    private final int offset;
    private final byte[] data;

    public LeakItem(int offset, byte[] data) {
        this.offset = offset;
        this.data = data == null ? new byte[0] : Arrays.copyOf(data, data.length);
    }

    public int getOffset() {
        return offset;
    }

    public byte[] getData() {
        return Arrays.copyOf(data, data.length);
    }

    public int getLength() {
        return data.length;
    }
}
