//
// Created by shihab on 6/5/19.
//

#ifndef IOTENCLAVE_SOCKETCONNECTION_H
#define IOTENCLAVE_SOCKETCONNECTION_H

#define LIMIT 1024

int establish_connection(int port);
int establish_connection_for_rule(int port);
int close_connection();
int close_connection_for_rule();

#endif //IOTENCLAVE_SOCKETCONNECTION_H
