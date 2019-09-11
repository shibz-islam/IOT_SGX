//
// Created by shihab on 6/5/19.
//

#ifndef IOTENCLAVE_MONGOHELPER_H
#define IOTENCLAVE_MONGOHELPER_H

int mongo_setup_db();
int mongo_fetch_db();
int mongo_update_db(struct device* s);


#endif //IOTENCLAVE_MONGOHELPER_H
