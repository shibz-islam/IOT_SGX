//
// Created by shihab on 6/5/19.
//

#include "JSONParser.h"
#include "Enclave_u.h"
#include <stdio.h>
#include <stdlib.h>
#include "string.h"
#include <jsoncpp/json/json.h>
#include "../cppcodec/base32_crockford.hpp"
#include "../cppcodec/base64_rfc4648.hpp"
#include "../cppcodec/base64.h"

std::string make_json_encrypted_data(char *text, size_t textLength, char *tag, size_t tagLength){
    Json::Value root;
    using base64 = cppcodec::base64_rfc4648;

    std::string encoded_text = base64::encode(text, textLength);
    std::string encoded_tag = base64::encode(tag, tagLength);

    root["cp"] = encoded_text;
    root["tag"] = encoded_tag;

    Json::FastWriter fastwriter;
    std::string message = fastwriter.write(root);
    //std::cout<< "json doc: " << message<<std::endl;

    return message;
}

std::string make_json_from_message(struct Message *ptr)
{
    Json::Value root;
//    root["deviceID"] = ptr->uid;

    using base64 = cppcodec::base64_rfc4648;

    std::string encoded_text = base64::encode(ptr->text, ptr->textLength);
    std::string encoded_tag = base64::encode(ptr->tag, ptr->tagLength);

    root["cp"] = encoded_text;
    root["tag"] = encoded_tag;

    Json::FastWriter fastwriter;
    std::string message = fastwriter.write(root);
    //std::cout<< "json doc: " << message<<std::endl;

    return message;
}


bool parse_data_with_tag(char *buffer, struct Message *ptr, bool isAllocated) {
    Json::Value jsonData;
    Json::Reader jsonReader;

    if (jsonReader.parse(buffer, jsonData)) {
        /*base64.cpp*/
        std::string decoded = base64_decode(jsonData["cp"].asString());
        //std::cout << "Decoding: " << decoded << std::endl;
        //std::cout << decoded.length() << std::endl;

        std::string decoded_tag = base64_decode(jsonData["tag"].asString());
        //std::cout << "Decoding: " << decoded_tag << std::endl;
        //std::cout << decoded_tag.length() << std::endl;

        if (!isAllocated){
            ptr->text = (char *) malloc((decoded.size()+1)*sizeof(char));
            ptr->textLength = decoded.length();
        }
        memcpy(ptr->text, (char *)decoded.c_str(), ptr->textLength);
        ptr->text[ptr->textLength] = '\0';
        //std::cout << ptr->text << std::endl;
        if (memcmp(ptr->text, decoded.c_str(), ptr->textLength) != 0){
            std::cout << "JSONParser::Copy Unsuccessful. Parsing incomplete!" << std::endl;
            if (!isAllocated) free(ptr->text);
            return false;
        }

        if (!isAllocated) {
            ptr->tag = (char *) malloc((decoded_tag.size() + 1) * sizeof(char));
            ptr->tagLength = decoded_tag.length();
        }
        memcpy(ptr->tag, decoded_tag.c_str(), ptr->tagLength);
        ptr->tag[ptr->tagLength] = '\0';
        //std::cout << ptr->tag << std::endl;
        if (memcmp(ptr->tag, decoded_tag.c_str(), ptr->tagLength) != 0){
            std::cout << "JSONParser:: Copy Unsuccessful. Parsing incomplete!" << std::endl;
            if (!isAllocated) free(ptr->tag);
            return false;
        }

        //std::cout << "Done Parsing!" << std::endl;
        return true;

    } else{
        std::cout << "JSONParser:: Something wrong with the parsing." << std::endl;
        return false;
    }
}

bool parse_data_length_with_tag(char *buffer, struct Message *ptr){
    Json::Value jsonData;
    Json::Reader jsonReader;

    if (jsonReader.parse(buffer, jsonData)) {
        /*base64.cpp*/
        std::string decoded = base64_decode(jsonData["cp"].asString());
        //std::cout << "Decoding: " << decoded << std::endl;
        //std::cout << decoded.length() << std::endl;

        std::string decoded_tag = base64_decode(jsonData["tag"].asString());
        //std::cout << "Decoding: " << decoded_tag << std::endl;
        //std::cout << decoded_tag.length() << std::endl;

        ptr->textLength = decoded.length();
        ptr->tagLength = decoded_tag.length();

        //std::cout << "Done Parsing!" << std::endl;
        return true;

    } else{
        std::cout << "JSONParser:: Something wrong with the parsing." << std::endl;
        return false;
    }
}

bool parse_data_with_cppcodec(char *buffer, struct Message *ptr) {
    Json::Value jsonData;
    Json::Reader jsonReader;

    if (jsonReader.parse(buffer, jsonData)) {
//        std::cout << "Successfully parsed JSON data" << std::endl;
        //std::cout << "\n\nJSON data received:" << std::endl;
        //std::cout << jsonData.toStyledString() << std::endl;

        /*CPPCodec*/

        using base64 = cppcodec::base64_rfc4648;
        std::vector<uint8_t> decoded = base64::decode(jsonData["ciphertext"].asString().c_str(), jsonData["ciphertext"].asString().length());
        //std::cout << "decoded size: " << decoded.size() << '\n';
        //std::cout << decoded.data() << std::endl;

        std::vector<uint8_t> decoded_tag = base64::decode(jsonData["tag"].asString().c_str(), jsonData["tag"].asString().length());
        //std::cout << "decoded_tag size: " << decoded_tag.size() << '\n';
        //std::cout << decoded_tag.data() << std::endl;

        char *temp = (char *) malloc((decoded.size()+1)*sizeof(char));
        memcpy(temp, decoded.data(), decoded.size());
        temp[decoded.size()] = '\0';
        //std::cout << strlen(temp) << std::endl;
        //std::cout << temp << std::endl;

        char *temp_tag = (char *) malloc((decoded_tag.size()+1)*sizeof(char));
        memcpy(temp_tag, decoded_tag.data(), decoded_tag.size());
        temp_tag[decoded_tag.size()] = '\0';
        //std::cout << strlen(temp_tag) << std::endl;
        //std::cout << temp_tag << std::endl;

        ptr->text = temp;
        ptr->tag = temp_tag;
        ptr->textLength = decoded.size();

        //std::cout << "Done Parsing!" << std::endl;
        return true;

    } else{
        std::cout << "JSONParser:: Something wrong with the parsing." << std::endl;
        return false;
    }
}


int parse_data_with_tag_index(char *buffer, struct Message *ptr, int index){
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

        ptr[index].text = temp;
        ptr[index].tag = temp_tag;
        std::cout << ptr[index].text << std::endl;

        std::cout << "Done Parsing!" << std::endl;

    } else{
        std::cout << "Something wrong with the parsing." << std::endl;
    }
    return 0;
}
