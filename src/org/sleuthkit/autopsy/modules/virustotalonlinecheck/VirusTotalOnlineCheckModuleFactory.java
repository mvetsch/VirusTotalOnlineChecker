package org.sleuthkit.autopsy.modules.virustotalonlinecheck;

import org.openide.util.NbBundle;
import org.openide.util.lookup.ServiceProvider;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModule;
import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.autopsy.ingest.IngestModuleFactory;
import org.sleuthkit.autopsy.ingest.IngestModuleGlobalSettingsPanel;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettingsPanel;

@ServiceProvider(service = IngestModuleFactory.class)
public class VirusTotalOnlineCheckModuleFactory implements IngestModuleFactory {

    private static final String VERSION_NUMBER = "1.0.0";

    @Override
    public String getModuleDisplayName() {
        return NbBundle.getMessage(VirusTotalOnlineCheckModuleFactory.class, "VirtusTotalOnlineCheckModuleFactory.moduleName");

    }

    @Override
    public String getModuleDescription() {
        return getModuleDisplayName();
    }

    @Override
    public String getModuleVersionNumber() {
        return VERSION_NUMBER;
    }

    @Override
    public boolean hasGlobalSettingsPanel() {
        return false;
    }

    @Override
    public IngestModuleGlobalSettingsPanel getGlobalSettingsPanel() {
        return new VirusTotalOnlineCheckGlobalSettingsPanel();
    }

    @Override
    public IngestModuleIngestJobSettings getDefaultIngestJobSettings() {
        return new VirusTotalOnlineCheckSettings();
    }

    @Override
    public boolean hasIngestJobSettingsPanel() {
        return true;
    }

    @Override
    public IngestModuleIngestJobSettingsPanel getIngestJobSettingsPanel(IngestModuleIngestJobSettings settings) {
        return new VirusTotalOnlineCheckJobSettingsPanel((VirusTotalOnlineCheckSettings) settings);
    }

    @Override
    public boolean isDataSourceIngestModuleFactory() {
        return false;
    }

    @Override
    public DataSourceIngestModule createDataSourceIngestModule(IngestModuleIngestJobSettings settings) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isFileIngestModuleFactory() {
        return true;
    }

    @Override
    public FileIngestModule createFileIngestModule(IngestModuleIngestJobSettings settings) {
        String apiKey = ((VirusTotalOnlineCheckSettings) settings).getApiKey();
        if(apiKey == null) { 
            apiKey = "";
        }
        return new VirusTotalOnlineCheckModule(apiKey);
    }
}
