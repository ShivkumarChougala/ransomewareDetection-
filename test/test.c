#include <stdio.h>
#include <unistd.h>
#include <curl/curl.h>

int main() {
    CURL *curl;
    CURLcode res;

    // Initialize libcurl
    curl = curl_easy_init();
    if (curl) {
        // Set target URL (harmless beacon)
        curl_easy_setopt(curl, CURLOPT_URL, "https://google.com");

        // Perform the request
        res = curl_easy_perform(curl);

        // Print result
        if (res != CURLE_OK)
            fprintf(stderr, "curl failed: %s\n", curl_easy_strerror(res));
        else
            printf("✅ Beacon sent.\n");

        // Cleanup
        curl_easy_cleanup(curl);
    }

    // Sleep to let tcpdump capture traffic
    sleep(2);

    return 0;
}
