//
// Created by shihab on 10/11/19.
//

#ifndef IOTENCLAVE_SOCKETMANAGER_H
#define IOTENCLAVE_SOCKETMANAGER_H

#define LIMIT 2048

class SocketManager {
private:
    int sockfd, newsockfd, port;
    void error(const char *msg);

public:
    SocketManager(int portNumber);
    int establish_connection();
    void close_connection();
};


#endif //IOTENCLAVE_SOCKETMANAGER_H
