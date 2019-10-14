//
// Created by shihab on 6/5/19.
//

#include "JSONParser.h"
#include "Enclave_u.h"
#include <stdio.h>
#include <stdlib.h>
#include <jsoncpp/json/json.h>
#include "../cppcodec/base32_crockford.hpp"
#include "../cppcodec/base64_rfc4648.hpp"



std::string make_json_from_message(struct message *ptr)
{
    Json::Value root;
//    root["deviceID"] = ptr->uid;


    using base64 = cppcodec::base64_rfc4648;

    std::string encoded_text = base64::encode(ptr->text, strlen(ptr->text));
    std::string encoded_tag = base64::encode(ptr->tag, strlen(ptr->tag));

    root["ciphertext"] = encoded_text;
    root["tag"] = encoded_tag;

    Json::FastWriter fastwriter;
    std::string message = fastwriter.write(root);
    std::cout<< "json doc: " << message<<std::endl;

    return message;
}


int parse_data_with_tag(char *buffer, struct message *ptr) {
    Json::Value jsonData;
    Json::Reader jsonReader;

    if (jsonReader.parse(buffer, jsonData)) {
//        std::cout << "Successfully parsed JSON data" << std::endl;
        std::cout << "\nJSON data received:" << std::endl;
        std::cout << jsonData.toStyledString() << std::endl;

        using base64 = cppcodec::base64_rfc4648;
        std::vector<uint8_t> decoded = base64::decode(jsonData["ciphertext"].asString().c_str(), jsonData["ciphertext"].asString().length());
        std::cout << "decoded size: " << decoded.size() << '\n';
        std::cout << decoded.data() << std::endl;

        std::vector<uint8_t> decoded_tag = base64::decode(jsonData["tag"].asString().c_str(), jsonData["tag"].asString().length());
        std::cout << "decoded_tag size: " << decoded_tag.size() << '\n';
        std::cout << decoded_tag.data() << std::endl;


        char *temp = (char *) malloc((decoded.size()+1)*sizeof(char));
        memcpy(temp, decoded.data(), decoded.size());
        temp[decoded.size()] = '\0';
        std::cout << temp << std::endl;
        std::cout << strlen(temp) << std::endl;

        char *temp_tag = (char *) malloc((decoded_tag.size()+1)*sizeof(char));
        memcpy(temp_tag, decoded_tag.data(), decoded_tag.size());
        temp_tag[decoded_tag.size()] = '\0';
        std::cout << temp_tag << std::endl;
        std::cout << strlen(temp_tag) << std::endl;

        ptr->text = temp;
        ptr->tag = temp_tag;
        std::cout << ptr->text << std::endl;

        std::cout << "Done Parsing!" << std::endl;

    } else{
        std::cout << "Something wrong with the parsing." << std::endl;
    }
    return 0;
}
