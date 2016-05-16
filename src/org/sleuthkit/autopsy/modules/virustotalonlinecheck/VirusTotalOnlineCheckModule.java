package org.sleuthkit.autopsy.modules.virustotalonlinecheck;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Semaphore;
import org.openide.util.Exceptions;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.services.TagsManager;
import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.HashUtility;
import org.sleuthkit.datamodel.TagName;
import org.sleuthkit.datamodel.TskCoreException;

class VirusTotalOnlineCheckModule implements FileIngestModule {

    private TagsManager tagsManager;
    private String tagNameString = "VirusTotal";
    private TagName moduleTag;

    private static LinkedList<ApiKey> apiKeyHolder = new LinkedList<>();
    private static Semaphore apiKeyHolderSemaphore = new Semaphore(1);
    private static List<String> addedApiKeys = new LinkedList<>();

    public VirusTotalOnlineCheckModule(String apiKey) {
        try {
            addApiKey(apiKey);
        } catch (InterruptedException ex) {
            
        }
    }

    private void addApiKey(String apiKey) throws InterruptedException {

        for (String key : apiKey.split(",")) {
            synchronized (addedApiKeys) {
                key = key.trim();
                if(key.length() < 64) {
                    continue;
                }
                if (!addedApiKeys.contains(key)) {
                    addedApiKeys.add(key);
                    apiKeyHolderSemaphore.acquire();
                    apiKeyHolder.add(new ApiKey(key));
                    apiKeyHolderSemaphore.release();
                }
            }
        }
        apiKeyHolderSemaphore.release();
    }

    @Override
    public ProcessResult process(AbstractFile file) {
        if (file.isFile() && file.canRead()) {
            if (file.getMd5Hash() == null) {
                try {
                    HashUtility.calculateMd5(file);
                } catch (IOException ex) {
                    return ProcessResult.ERROR;
                }
            }
            try {
                ApiKey processApiKey = blockUntilApiKeyIsFree();
                VirusTotalReport report = processApiKey.getReport(file.getMd5Hash());
                releaseApiKey(processApiKey);

                if (report == null) {
                    return ProcessResult.ERROR;
                }

                if (report.isKnown()) {
                    try {
                        addVirusTotalReportTag(file, report);
                    } catch (TskCoreException ex) {
                        return ProcessResult.ERROR;
                    }
                }

            } catch (InterruptedException ex) {
                return ProcessResult.ERROR;
            }
        }
        return ProcessResult.OK;
    }

    @Override
    public void shutDown() {
    }

    @Override
    public void startUp(IngestJobContext context) throws IngestModuleException {
        if(addedApiKeys.size() == 0) { 
            throw new IngestModuleException("no API key configured");
        }
        tagsManager = Case.getCurrentCase().getServices().getTagsManager();
        try {
            moduleTag = tagsManager.addTagName(tagNameString, "All Files ending wiht .exe", TagName.HTML_COLOR.LIME);
        } catch (TagsManager.TagNameAlreadyExistsException ex) {
            try {
                for (TagName tagName : tagsManager.getAllTagNames()) {
                    if (tagName.getDisplayName().equals(tagNameString)) {
                        moduleTag = tagName;
                        return;
                    }
                }
            } catch (TskCoreException ex1) {
                Exceptions.printStackTrace(ex1);
            }
        } catch (TskCoreException ex) {
            Exceptions.printStackTrace(ex);
        }
    }

    private void addVirusTotalReportTag(AbstractFile file, VirusTotalReport report) throws TskCoreException {
        tagsManager.addContentTag(file, moduleTag, "More information on " + report.getPermaLink());
    }

    private ApiKey blockUntilApiKeyIsFree() throws InterruptedException {

        apiKeyHolderSemaphore.acquire();
        while (apiKeyHolder.size() < 1) {
            try {
                apiKeyHolderSemaphore.release();
                Thread.sleep(1000);
                apiKeyHolderSemaphore.acquire();
            } catch (InterruptedException ex) {

            }
        }

        int smallestIndex = Integer.MAX_VALUE;
        long smallestWaitingSpan = Long.MAX_VALUE;

        for (int i = 0; i < apiKeyHolder.size(); i++) {
            if (apiKeyHolder.get(i).getTimeUntilNextPossibleRequest() < smallestWaitingSpan) {
                smallestIndex = i;
                smallestWaitingSpan = apiKeyHolder.get(i).getTimeUntilNextPossibleRequest();
            }
        }

        ApiKey result = apiKeyHolder.remove(smallestIndex);
        apiKeyHolderSemaphore.release();
        return result;
    }

    private void releaseApiKey(ApiKey apiKey) throws InterruptedException {
        apiKeyHolderSemaphore.acquire();
        apiKeyHolder.add(apiKey);
        apiKeyHolderSemaphore.release();
    }
}
