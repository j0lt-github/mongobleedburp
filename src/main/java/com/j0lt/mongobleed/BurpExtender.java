package com.j0lt.mongobleed;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import burp.ITab;

import java.awt.Component;

public class BurpExtender implements IBurpExtender, ITab, IExtensionStateListener {
    private MongobleedTab tab;
    private Thread shutdownHook;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("MongoBleed Detector");
        tab = new MongobleedTab(callbacks);
        callbacks.addSuiteTab(this);
        callbacks.registerExtensionStateListener(this);
        shutdownHook = new Thread(new Runnable() {
            @Override
            public void run() {
                if (tab != null) {
                    tab.shutdown();
                }
            }
        }, "mongobleed-shutdown");
        Runtime.getRuntime().addShutdownHook(shutdownHook);
        callbacks.printOutput("MongoBleed extension loaded: creator j0lt");
    }

    @Override
    public String getTabCaption() {
        return "MongoBleed";
    }

    @Override
    public Component getUiComponent() {
        return tab.getRoot();
    }

    @Override
    public void extensionUnloaded() {
        if (tab != null) {
            tab.shutdown();
        }
        if (shutdownHook != null) {
            try {
                Runtime.getRuntime().removeShutdownHook(shutdownHook);
            } catch (IllegalStateException ignored) {
            }
            shutdownHook = null;
        }
    }
}
