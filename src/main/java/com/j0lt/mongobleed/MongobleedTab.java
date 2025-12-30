package com.j0lt.mongobleed;

import burp.IBurpExtenderCallbacks;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingWorker;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public class MongobleedTab {
    private final IBurpExtenderCallbacks callbacks;
    private final MongobleedScanner scanner = new MongobleedScanner();
    private final JPanel root;

    private static final int DEFAULT_STEP = 1;
    private static final int DEFAULT_BUFFER_PAD = 500;
    private static final int DEFAULT_TIMEOUT_MS = 2000;
    private static final int DEFAULT_MAX_PROBES = 0;
    private static final int DEFAULT_MIN_LEAK_LEN = 4;
    private static final int DEFAULT_MAX_LEAKS = 200;
    private static final int DEFAULT_MAX_TOTAL_BYTES = 500000;
    private static final int DEFAULT_MAX_RESPONSE_BYTES = 2000000;
    private static final boolean DEFAULT_STOP_ON_FIRST = false;

    private JTextField hostField;
    private JTextField portField;
    private JTextField minOffsetField;
    private JTextField maxOffsetField;

    private JButton runButton;
    private JButton stopButton;
    private JButton clearButton;
    private JButton copyButton;

    private JLabel statusLabel;
    private JLabel summaryLabel;
    private JLabel keywordLabel;
    private JProgressBar progressBar;

    private LeakTableModel tableModel;
    private JTable leakTable;
    private JTextArea hexArea;
    private JTextArea textArea;
    private JTextField filterField;

    private final AtomicReference<ScanWorker> currentWorker = new AtomicReference<>();

    public MongobleedTab(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.root = new JPanel(new BorderLayout());

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Manual Test", buildManualPanel());
        tabs.addTab("About", buildAboutPanel());

        callbacks.customizeUiComponent(tabs);
        root.add(tabs, BorderLayout.CENTER);
    }

    public Component getRoot() {
        return root;
    }

    private JComponent buildManualPanel() {
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.35);

        JPanel optionsPanel = new JPanel();
        optionsPanel.setLayout(new GridBagLayout());
        optionsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, 10, 0);

        optionsPanel.add(buildTargetPanel(), gbc);
        gbc.gridy++;
        optionsPanel.add(buildOffsetsPanel(), gbc);
        gbc.gridy++;
        optionsPanel.add(buildControlPanel(), gbc);
        gbc.gridy++;
        optionsPanel.add(buildStatusPanel(), gbc);
        gbc.gridy++;
        gbc.weighty = 1.0;
        optionsPanel.add(new JPanel(), gbc);

        JPanel resultsPanel = buildResultsPanel();

        splitPane.setLeftComponent(new JScrollPane(optionsPanel));
        splitPane.setRightComponent(resultsPanel);

        return splitPane;
    }

    private JPanel buildTargetPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Target"));

        hostField = new JTextField("127.0.0.1", 14);
        portField = new JTextField("27017", 6);

        GridBagConstraints gbc = fieldConstraints();
        addFieldRow(panel, gbc, "Host", hostField);
        addFieldRow(panel, gbc, "Port", portField);

        return panel;
    }

    private JPanel buildOffsetsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Offsets"));

        minOffsetField = new JTextField("20", 6);
        maxOffsetField = new JTextField("8192", 6);

        GridBagConstraints gbc = fieldConstraints();
        addFieldRow(panel, gbc, "Min", minOffsetField);
        addFieldRow(panel, gbc, "Max", maxOffsetField);

        return panel;
    }

    private JPanel buildControlPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        panel.setBorder(BorderFactory.createTitledBorder("Controls"));

        runButton = new JButton("Run Scan");
        stopButton = new JButton("Stop");
        clearButton = new JButton("Clear");
        copyButton = new JButton("Copy Selected");
        stopButton.setEnabled(false);

        runButton.addActionListener(e -> startScan());
        stopButton.addActionListener(e -> stopScan());
        clearButton.addActionListener(e -> clearResults());
        copyButton.addActionListener(e -> copySelected());

        panel.add(runButton);
        panel.add(stopButton);
        panel.add(clearButton);
        panel.add(copyButton);

        return panel;
    }

    private JPanel buildStatusPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Status"));

        summaryLabel = new JLabel("Idle");
        keywordLabel = new JLabel("Keywords: none");
        statusLabel = new JLabel("Ready");
        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        progressBar.setPreferredSize(new Dimension(220, 18));

        GridBagConstraints gbc = fieldConstraints();
        gbc.gridwidth = 2;
        panel.add(summaryLabel, gbc);
        gbc.gridy++;
        panel.add(keywordLabel, gbc);
        gbc.gridy++;
        panel.add(statusLabel, gbc);
        gbc.gridy++;
        panel.add(progressBar, gbc);

        return panel;
    }

    private JPanel buildResultsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        tableModel = new LeakTableModel();
        leakTable = new JTable(tableModel);
        leakTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        leakTable.setAutoCreateRowSorter(true);

        TableRowSorter<LeakTableModel> sorter = new TableRowSorter<>(tableModel);
        leakTable.setRowSorter(sorter);

        filterField = new JTextField();
        filterField.addActionListener(e -> applyFilter(sorter));
        filterField.getDocument().addDocumentListener(new SimpleDocumentListener(() -> applyFilter(sorter)));

        leakTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateDetails();
            }
        });

        JPanel filterPanel = new JPanel(new BorderLayout());
        filterPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
        filterPanel.add(new JLabel("Filter"), BorderLayout.WEST);
        filterPanel.add(filterField, BorderLayout.CENTER);

        Font monoFont = new Font(Font.MONOSPACED, Font.PLAIN, 12);
        hexArea = new JTextArea();
        hexArea.setEditable(false);
        hexArea.setFont(monoFont);
        textArea = new JTextArea();
        textArea.setEditable(false);
        textArea.setFont(monoFont);

        JTabbedPane detailsTabs = new JTabbedPane();
        detailsTabs.addTab("Hex + ASCII", new JScrollPane(hexArea));
        detailsTabs.addTab("Text", new JScrollPane(textArea));

        JSplitPane resultsSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        resultsSplit.setResizeWeight(0.6);
        resultsSplit.setTopComponent(new JScrollPane(leakTable));
        resultsSplit.setBottomComponent(detailsTabs);

        panel.add(filterPanel, BorderLayout.NORTH);
        panel.add(resultsSplit, BorderLayout.CENTER);

        return panel;
    }

    private JComponent buildAboutPanel() {
        JTextArea about = new JTextArea();
        about.setEditable(false);
        about.setLineWrap(true);
        about.setWrapStyleWord(true);
        about.setText(
                "MongoBleed Burp Extension\n" +
                "CVE-2025-14847 detector and manual tester.\n\n" +
                "Creator: j0lt\n\n" +
                "Repository: https://github.com/j0lt-github/mongobleedburp\n\n" +
                "The extension performs a zlib-compressed OP_MSG probe that can expose " +
                "uninitialized memory in vulnerable MongoDB versions. Leaks are kept in " +
                "memory only and displayed in the UI. Use only for authorized security testing."
        );
        return new JScrollPane(about);
    }

    private void startScan() {
        if (currentWorker.get() != null) {
            return;
        }
        ScanConfig config;
        try {
            config = buildManualConfig();
        } catch (IllegalArgumentException ex) {
            JOptionPane.showMessageDialog(root, ex.getMessage(), "Invalid Settings", JOptionPane.ERROR_MESSAGE);
            return;
        }

        clearResults();

        int estimatedProbes = estimateProbes(config);
        progressBar.setMinimum(0);
        progressBar.setMaximum(Math.max(1, estimatedProbes));
        progressBar.setValue(0);
        progressBar.setString("0 / " + estimatedProbes);

        runButton.setEnabled(false);
        stopButton.setEnabled(true);
        statusLabel.setText("Running scan...");

        ScanWorker worker = new ScanWorker(config);
        currentWorker.set(worker);
        worker.execute();
    }

    private void stopScan() {
        ScanWorker worker = currentWorker.get();
        if (worker != null) {
            worker.requestStop();
            statusLabel.setText("Stopping...");
        }
    }

    private void clearResults() {
        tableModel.setLeaks(new ArrayList<LeakItem>());
        hexArea.setText("");
        textArea.setText("");
        summaryLabel.setText("Idle");
        keywordLabel.setText("Keywords: none");
        statusLabel.setText("Ready");
        progressBar.setValue(0);
        progressBar.setString("0 / 0");
    }

    private void copySelected() {
        int row = leakTable.getSelectedRow();
        if (row < 0) {
            return;
        }
        int modelRow = leakTable.convertRowIndexToModel(row);
        LeakItem item = tableModel.getLeakAt(modelRow);
        String dump = FormatUtils.hexAsciiDump(item.getData(), 16);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(dump), null);
        statusLabel.setText("Copied selected leak");
    }

    private void updateDetails() {
        int row = leakTable.getSelectedRow();
        if (row < 0) {
            hexArea.setText("");
            textArea.setText("");
            return;
        }
        int modelRow = leakTable.convertRowIndexToModel(row);
        LeakItem item = tableModel.getLeakAt(modelRow);
        hexArea.setText(FormatUtils.hexAsciiDump(item.getData(), 16));
        textArea.setText(FormatUtils.safeUtf8(item.getData()));
    }

    private void applyFilter(TableRowSorter<LeakTableModel> sorter) {
        String text = filterField.getText().trim();
        if (text.isEmpty()) {
            sorter.setRowFilter(null);
        } else {
            sorter.setRowFilter(RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(text)));
        }
    }

    private ScanConfig buildManualConfig() {
        String host = hostField.getText().trim();
        if (host.isEmpty()) {
            host = "127.0.0.1";
        }

        int port = parseInt(portField, "port", 1);
        if (port > 65535) {
            throw new IllegalArgumentException("port must be <= 65535");
        }
        int minOffset = parseInt(minOffsetField, "min offset", 1);
        int maxOffset = parseInt(maxOffsetField, "max offset", minOffset + 1);
        int step = DEFAULT_STEP;
        int bufferPad = DEFAULT_BUFFER_PAD;
        int timeout = DEFAULT_TIMEOUT_MS;
        int maxProbes = DEFAULT_MAX_PROBES;
        int minLeakLen = DEFAULT_MIN_LEAK_LEN;
        int maxLeaks = DEFAULT_MAX_LEAKS;
        int maxBytes = DEFAULT_MAX_TOTAL_BYTES;
        int maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES;

        if (maxOffset <= minOffset) {
            throw new IllegalArgumentException("max offset must be greater than min offset");
        }

        return new ScanConfig(
                host,
                port,
                minOffset,
                maxOffset,
                step,
                bufferPad,
                timeout,
                maxLeaks,
                maxBytes,
                maxResponseBytes,
                minLeakLen,
                DEFAULT_STOP_ON_FIRST,
                maxProbes
        );
    }

    private int estimateProbes(ScanConfig config) {
        int span = config.maxOffset - config.minOffset;
        int count = span / Math.max(1, config.step) + 1;
        if (config.maxProbes > 0) {
            count = Math.min(count, config.maxProbes);
        }
        return count;
    }

    private int parseInt(JTextField field, String label, int min) {
        String raw = field.getText().trim();
        try {
            int value = Integer.parseInt(raw);
            if (value < min) {
                throw new IllegalArgumentException(label + " must be >= " + min);
            }
            return value;
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("invalid " + label + ": " + raw);
        }
    }

    private GridBagConstraints fieldConstraints() {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new Insets(2, 2, 2, 2);
        gbc.anchor = GridBagConstraints.WEST;
        return gbc;
    }

    private void addFieldRow(JPanel panel, GridBagConstraints gbc, String label, JTextField field) {
        gbc.gridx = 0;
        gbc.weightx = 0;
        panel.add(new JLabel(label), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(field, gbc);
        gbc.gridy++;
    }

    private final class ScanWorker extends SwingWorker<ScanResult, ScanProgress> implements MongobleedScanner.ScanProgressListener {
        private final ScanConfig config;
        private final AtomicBoolean stopRequested = new AtomicBoolean(false);

        private ScanWorker(ScanConfig config) {
            this.config = config;
        }

        @Override
        protected ScanResult doInBackground() {
            return scanner.scan(config, this);
        }

        @Override
        protected void process(List<ScanProgress> chunks) {
            if (chunks.isEmpty()) {
                return;
            }
            ScanProgress progress = chunks.get(chunks.size() - 1);
            progressBar.setValue(Math.min(progressBar.getMaximum(), progress.probes));
            progressBar.setString(progress.probes + " / " + progressBar.getMaximum());
            statusLabel.setText("Offset " + progress.offset + " | leaks " + progress.leaksFound + " | bytes " + progress.totalBytes);
        }

        @Override
        protected void done() {
            ScanResult result;
            try {
                result = get();
            } catch (Exception ex) {
                statusLabel.setText("Scan failed: " + ex.getMessage());
                runButton.setEnabled(true);
                stopButton.setEnabled(false);
                currentWorker.set(null);
                return;
            }

            tableModel.setLeaks(result.getLeaks());
            summaryLabel.setText(
                    "Probes: " + result.getProbesTried() +
                            " | Leaks: " + result.getLeaks().size() +
                            " | Bytes: " + result.getTotalBytes() +
                            " | Duration: " + (result.getDurationMs() / 1000.0) + "s"
            );

            if (result.getKeywordHits().isEmpty()) {
                keywordLabel.setText("Keywords: none");
            } else {
                keywordLabel.setText("Keywords: " + String.join(", ", result.getKeywordHits()));
            }

            statusLabel.setText(result.isCancelled() ? "Scan cancelled" : "Scan complete");
            progressBar.setValue(progressBar.getMaximum());
            progressBar.setString(progressBar.getMaximum() + " / " + progressBar.getMaximum());

            runButton.setEnabled(true);
            stopButton.setEnabled(false);
            currentWorker.set(null);
        }

        @Override
        public void onProgress(int offset, int maxOffset, int probes, int leaksFound, int totalBytes) {
            publish(new ScanProgress(offset, probes, leaksFound, totalBytes));
        }

        @Override
        public boolean isStopRequested() {
            return stopRequested.get();
        }

        private void requestStop() {
            stopRequested.set(true);
        }
    }

    private static final class ScanProgress {
        private final int offset;
        private final int probes;
        private final int leaksFound;
        private final int totalBytes;

        private ScanProgress(int offset, int probes, int leaksFound, int totalBytes) {
            this.offset = offset;
            this.probes = probes;
            this.leaksFound = leaksFound;
            this.totalBytes = totalBytes;
        }
    }

    private static final class LeakTableModel extends AbstractTableModel {
        private final String[] columns = new String[] { "Offset", "Length", "Preview" };
        private List<LeakItem> leaks = new ArrayList<>();

        public void setLeaks(List<LeakItem> leaks) {
            this.leaks = leaks == null ? new ArrayList<LeakItem>() : new ArrayList<>(leaks);
            fireTableDataChanged();
        }

        public LeakItem getLeakAt(int row) {
            return leaks.get(row);
        }

        @Override
        public int getRowCount() {
            return leaks.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            LeakItem item = leaks.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return item.getOffset();
                case 1:
                    return item.getLength();
                case 2:
                    return FormatUtils.preview(item.getData(), 120);
                default:
                    return "";
            }
        }
    }

    private static final class SimpleDocumentListener implements javax.swing.event.DocumentListener {
        private final Runnable onChange;

        private SimpleDocumentListener(Runnable onChange) {
            this.onChange = onChange;
        }

        @Override
        public void insertUpdate(javax.swing.event.DocumentEvent e) {
            onChange.run();
        }

        @Override
        public void removeUpdate(javax.swing.event.DocumentEvent e) {
            onChange.run();
        }

        @Override
        public void changedUpdate(javax.swing.event.DocumentEvent e) {
            onChange.run();
        }
    }
}
