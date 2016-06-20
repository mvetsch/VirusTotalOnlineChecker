package org.sleuthkit.autopsy.modules.virustotalonlinecheck;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Date;
import java.util.LinkedList;
import org.json.JSONObject;

public class ApiKey {

    private static final String apiUrl = "https://www.virustotal.com/vtapi/v2/file/report";

    private final static int allowedRequestsPerMinute = 4;
    private final static long msOfAMinute = 60 * 1000;
    private String apiKey;

    private LinkedList<Date> lastRequests = new LinkedList<>();

    public ApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public long getTimeUntilNextPossibleRequest() {
        if (lastRequests.size() < allowedRequestsPerMinute) {
            return 0;
        }

        Date relevantTimeStamp = lastRequests.get(lastRequests.size() - allowedRequestsPerMinute);
        long timeToWait = msOfAMinute - (new Date().getTime() - relevantTimeStamp.getTime());

        if (timeToWait < 0) {
            timeToWait = 0;
        }
        return timeToWait;
    }

    public VirusTotalReport getReport(String resource) throws InterruptedException {
        String urlString = apiUrl + "?apikey=" + apiKey + "&resource=" + resource;
        URL url = null;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException ex) {
            return null;
        }

        boolean successful = false;
        while (!successful) {
            long time = getTimeUntilNextPossibleRequest();
            Thread.sleep(time);

            VirusTotalReport result = getResult(url);
            if (result != null) {
                lastRequests.add(new Date());
                return result;

            }
        }
        return null;
    }

    private VirusTotalReport getResult(URL url) {

        JSONObject response = null;

        try {
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            InputStream is = connection.getInputStream();

            int ret = connection.getResponseCode();
            if (ret == 204) {
                return null;
            }

            BufferedReader streamReader = new BufferedReader(new InputStreamReader(is, "UTF-8"));
            StringBuilder responseStrBuilder = new StringBuilder();

            String inputStr;
            while ((inputStr = streamReader.readLine()) != null) {
                responseStrBuilder.append(inputStr);
            }
            String responseString = responseStrBuilder.toString();
            response = new JSONObject(responseString);

        } catch (IOException ex) {
            return new VirusTotalReport();
        }

        try {
            int positives = response.getInt("positives");
            if (positives > 0) {
                String permaLink = response.getString("permalink");
                return new VirusTotalReport(permaLink);
            }
        } catch (Exception e) {
        }
        return new VirusTotalReport();
    }

}
