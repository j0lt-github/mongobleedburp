package com.j0lt.mongobleed;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.ITab;

import java.awt.Component;

public class BurpExtender implements IBurpExtender, ITab {
    private MongobleedTab tab;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("MongoBleed Detector (j0lt)");
        tab = new MongobleedTab(callbacks);
        callbacks.addSuiteTab(this);
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
}
