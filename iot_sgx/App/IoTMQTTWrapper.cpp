//
// Created by shihab on 3/23/20.
//


#include "IoTMQTTWrapper.h"
#include "App.h"

//std::string topic_name = "topic/iot/deviceid123";

void doSomething(){
    for (int i = 0; i < 20; ++i) {
        std::string temp = "message number " + std::to_string(i+1);

        //mosquitto_publish(NULL, topic_name.c_str(), temp.length(), temp.c_str());
    }
}

IoTMQTTWrapper::IoTMQTTWrapper(const char *id, const char *host, int port) {
    mosqpp::lib_init();			// Initialize libmosquitto

    int keepalive = 120;        // seconds
    connect(host, port, keepalive);
    topic_name = "";
}

IoTMQTTWrapper::~IoTMQTTWrapper() {

}

void IoTMQTTWrapper::on_connect(int rc) {
    printf("MQTT Connected with code %d. \n", rc);

    if(rc==0){

    }else {
        printf("Error! %s\n",strerror(rc));
    }
}

void IoTMQTTWrapper::on_subcribe(int mid, int qos_count, const int *granted_qos) {
    printf("Subscription succeeded. \n");
}

void IoTMQTTWrapper::on_message(const struct mosquitto_message *message) {
    if(message->topic == topic_name.c_str()){
        printf("Got message from topic");
        char *msg = (char *) malloc((message->payloadlen+1)*sizeof(char));
        memcpy(msg, message->payload, message->payloadlen);
        printf("@Message: %s", msg);
        didReceiveMessageFromMQTT(msg);
    }
    else{
        printf("Error! Unknown topic.");
    }

}

void IoTMQTTWrapper::on_publish(int mid) {
    printf("Mid %d\n", mid);
}

void IoTMQTTWrapper::publishMessage(const char *topic, const char *msg) {
    int rc = publish(NULL, topic, strlen(msg), msg);
    if(rc==0){

    }else {
        printf("%s\n",strerror(rc));
    }
}

void IoTMQTTWrapper::subscribeTopic(const char *topic){
    printf("topic: %s\n", topic);
    int rc = subscribe(NULL, topic);
    if(rc==0){
        printf("Subscription successful\n");
    }else {
        printf("%s\n",strerror(rc));
    }
}