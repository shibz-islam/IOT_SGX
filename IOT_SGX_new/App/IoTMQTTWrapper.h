//
// Created by shihab on 3/23/20.
//

#ifndef TESTINGMQTT_IOTMQTTWRAPPER_H
#define TESTINGMQTT_IOTMQTTWRAPPER_H

#include <iostream>
#include <mosquittopp.h>
#include "string.h"
//#include <mosquitto.h>

class IoTMQTTWrapper: public mosqpp::mosquittopp {
private:
    std::string topic_name;
public:
    IoTMQTTWrapper(const char *id, const char *host, int port);
    ~IoTMQTTWrapper();
    bool publishMessage(const char *topic, const char *msg);
    void subscribeTopic(const char *topic);

    void on_connect(int rc);
    void on_message(const struct mosquitto_message *message);
    void on_subcribe(int mid, int qos_count, const int *granted_qos);
    void on_publish(int mid);
};


#endif //TESTINGMQTT_IOTMQTTWRAPPER_H
