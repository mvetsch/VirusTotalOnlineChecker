package org.sleuthkit.autopsy.modules.virustotalonlinecheck;

import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;

public class VirusTotalOnlineCheckSettings implements IngestModuleIngestJobSettings {

    private String apiKey = "";
    private static final long serialVersionUID = 1L;

    @Override
    public long getVersionNumber() {
        return serialVersionUID;
    }

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

}
