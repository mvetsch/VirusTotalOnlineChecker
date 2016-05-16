package org.sleuthkit.autopsy.modules.virustotalonlinecheck;

public class VirusTotalReport {

    private boolean isKnown;
    private String permaLink;

    public VirusTotalReport() {
        this.isKnown = false;
    }

    public VirusTotalReport(String permaLink) {
        this.permaLink = permaLink;
        this.isKnown = true;
    }

    public boolean isKnown() {
        return isKnown;
    }

    public String getPermaLink() {
        return permaLink;
    }
}
