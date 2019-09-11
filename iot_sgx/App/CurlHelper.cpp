//
// Created by shihab on 6/5/19.
//

#include "CurlHelper.h"
#include "Enclave_u.h"
#include <stdio.h>
#include <stdlib.h>

#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <curl/curl.h>

#include <jsoncpp/json/json.h>
#include <curl/curl.h>

namespace
{
    std::size_t callback(
            const char* in,
            std::size_t size,
            std::size_t num,
            std::string* out)
    {
        const std::size_t totalBytes(size * num);
        out->append(in, totalBytes);
        return totalBytes;
    }
}

int get_iot_data(struct device *ptr)
{
    const std::string url("http://192.168.2.2/api/bzPrEQr51gcpVhNeDn3HOT13HbOLJDiuxbxtnUxO/lights");

    CURL* curl = curl_easy_init();

    // Set remote URL.
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    // Don't bother trying IPv6, which would increase DNS resolution time.
    curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);

    // Don't wait forever, time out after 10 seconds.
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);

    // Follow HTTP redirects if necessary.
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    // Response information.
    long httpCode(0);
    std::unique_ptr<std::string> httpData(new std::string());

    // Hook up data handling function.
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);

    // Hook up data container (will be passed as the last parameter to the
    // callback handling function).  Can be any pointer type, since it will
    // internally be passed as a void pointer.
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());

    // Run our HTTP GET command, capture the HTTP response code, and clean up.
    curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_easy_cleanup(curl);

    if (httpCode == 200)
    {
        std::cout << "\nGot successful response from " << url << std::endl;

        // Response looks good - done using Curl now.  Try to parse the results
        // and print them out.
        Json::Value jsonData;
        Json::Reader jsonReader;

        if (jsonReader.parse(*httpData.get(), jsonData))
        {
            std::cout << "Successfully parsed JSON data" << std::endl;
            std::cout << "\nJSON data received:" << std::endl;
            std::cout << jsonData.toStyledString() << std::endl;

            const std::string dateString(jsonData["date"].asString());
            const std::size_t unixTimeMs(
                    jsonData["milliseconds_since_epoch"].asUInt64());
            const std::string timeString(jsonData["time"].asString());

            std::cout << "Natively parsed:" << std::endl;
            std::cout << "\tDate string: " << dateString << std::endl;
            std::cout << "\tUnix timeMs: " << unixTimeMs << std::endl;
            std::cout << "\tTime string: " << timeString << std::endl;
            std::cout << "\tsize: " << jsonData.size() << std::endl;

            for( Json::ValueIterator itr = jsonData.begin() ; itr != jsonData.end() ; itr++ ) {
                // Print depth.
                std::cout << "\tkey: " << itr.key() << std::endl;
            }
            std::cout << "\tuniqueid: " << jsonData["1"]["uniqueid"].asString() << std::endl;
            std::cout << "\tstate: " << jsonData["1"]["state"]["on"].asString() << std::endl;
            std::cout << std::endl;

            char *uid = new char[jsonData["1"]["uniqueid"].asString().length() + 1];
            strcpy(uid, jsonData["1"]["uniqueid"].asString().c_str());
            char *state = new char[jsonData["1"]["state"]["on"].asString().length() + 1];
            strcpy(state, jsonData["1"]["state"]["on"].asString().c_str());
            printf("%s %s\n", uid,state);

            ptr->uid = uid;
            ptr->state = state;
        }
        else
        {
            std::cout << "Could not parse HTTP data as JSON" << std::endl;
            std::cout << "HTTP data was:\n" << *httpData.get() << std::endl;
            return 1;
        }
    }
    else
    {
        std::cout << "Couldn't GET from " << url << " - exiting" << std::endl;
        return 1;
    }
}