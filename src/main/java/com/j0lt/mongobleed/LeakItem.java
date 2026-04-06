package com.j0lt.mongobleed;

public class LeakItem {
    private final int offset;
    private final int length;
    private final String preview;
    private final long recordOffset;

    public LeakItem(int offset, int length, String preview, long recordOffset) {
        this.offset = offset;
        this.length = length;
        this.preview = preview == null ? "" : preview;
        this.recordOffset = recordOffset;
    }

    public int getOffset() {
        return offset;
    }

    public int getLength() {
        return length;
    }

    public String getPreview() {
        return preview;
    }

    public long getRecordOffset() {
        return recordOffset;
    }
}
