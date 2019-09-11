//
// Created by shihab on 3/24/19.
//
#include "bridge.h"
#include <python2.7/Python.h>


std::vector<Sensor*> connect(std::string fileName, std::string funcName){
    PyObject *pName, *pModule, *pDict, *pFunc, *pList, *pKey, *pValue;
    std::vector<Sensor*> sensor_vec;

    Py_Initialize();

//    PyRun_SimpleString("import sys");
//    PyRun_SimpleString("sys.path.append(\".\")");
    PyRun_SimpleString("import sys\n" "import os");
    PyRun_SimpleString("sys.path.append( os.getcwd() +'/App/')"); //Specify the directory where the python file might be in
    PyRun_SimpleString("sys.path.append('/home/shihab/anaconda3/lib/python3.7/site-packages/')"); //Specify python packages directory

    pName = PyUnicode_FromString(fileName.c_str());
    /* Error checking of pName left out */

    printf("In the bridge...\n");

    pModule = PyImport_Import(pName);
    Py_DECREF(pName);

    if (pModule != NULL) {
        pFunc = PyObject_GetAttrString(pModule, funcName.c_str());
        /* pFunc is a new reference */

        if (pFunc && PyCallable_Check(pFunc)) {
            pValue = PyObject_CallObject(pFunc, NULL); //List of Dict objects
            if (pValue != NULL) {
                printf("size of the list: %ld\n", PyList_Size(pValue));

                for (int j = 0; j < PyList_Size(pValue); ++j) { //Loop through the list
                    pDict = PyList_GetItem(pValue, j);
                    pList = PyDict_Keys(pDict);
                    Sensor *sensor = new Sensor();

                    for (int k = 0; k < PyList_Size(pList); k++){
                        pKey = PyList_GetItem(pList, k);
                        pName = PyDict_GetItem(pDict, pKey);
//                        printf("%ld -> %s\n", k+1, PyString_AsString(pKey));

                        if(strcmp(PyString_AsString(pKey), "n") == 0)
                            sensor->name = PyString_AsString(pName);
                        else if (strcmp(PyString_AsString(pKey), "v") == 0)
                            sensor->value = int(PyInt_AsLong(pName));
                        else
                            sensor->id = PyString_AsString(pName);

//                        if(PyInt_Check(pName)){
//                            printf("%s: %ld\n", PyString_AsString(pKey), PyLong_AsLong(pName));
//                            sensor->value = int(PyInt_AsLong(pName));
//                        } else if (PyObject_TypeCheck(pName, &PyBaseString_Type)){
//                            printf("%s: %s\n", PyString_AsString(pKey), PyString_AsString(pName));
//                            if(strcmp(PyString_AsString(pKey), "n") == 0)
//                                sensor->name = PyString_AsString(pName);
//                            else
//                                sensor->id = PyString_AsString(pName);
//                        }
                    }
                    sensor_vec.push_back(sensor);
                }
                Py_DECREF(pValue);
            }
            else {
                Py_DECREF(pFunc);
                Py_DECREF(pModule);
                PyErr_Print();
                fprintf(stderr,"Call failed\n");
            }
        }
        else {
            if (PyErr_Occurred())
                PyErr_Print();
            fprintf(stderr, "Cannot find function \"%s\"\n", funcName.c_str());
        }
        Py_XDECREF(pFunc);
        Py_DECREF(pModule);
    }
    else {
        PyErr_Print();
        fprintf(stderr, "Failed to load \"%s\"\n", fileName.c_str());
    }
    Py_Finalize();

    return sensor_vec;
}


char* encode_string(std::string value){
    std::string fileName = "unicode_converter";
    std::string funcName = "encode_to_latin1";
    PyObject *pName, *pModule, *pFunc, *pMsg, *pVar, *pValue;
    char *result;

//    std::string temp = "\\u00d3\\u00d9\\b\\u00fb";
//    std::string temp = "Hello World";

    pVar = Py_BuildValue("s", value.c_str());
    pMsg = Py_BuildValue("(O)", pVar);
//    printf("%s \n", PyBytes_AS_STRING(pMsg));

    Py_Initialize();
    PyRun_SimpleString("import sys\n" "import os");
    PyRun_SimpleString("sys.path.append( os.getcwd() +'/App/')");
    PyRun_SimpleString("sys.path.append('/home/shihab/anaconda3/lib/python3.7/site-packages/')");


    pName = PyUnicode_FromString(fileName.c_str());
    pModule = PyImport_Import(pName);
    Py_DECREF(pName);

    if (pModule != NULL) {
        pFunc = PyObject_GetAttrString(pModule, funcName.c_str());
        if (pFunc && PyCallable_Check(pFunc)) {
            pValue = PyObject_CallObject(pFunc, pMsg);
            if (pValue != NULL) {
                printf("Type: %d\n", PyObject_TypeCheck(pName, &PyUnicode_Type));
                printf("PyUnicode_Check: %d\n", PyUnicode_Check(pName));
                const char* c_str = PyUnicode_AS_DATA(pValue);
                printf("The python unicode string is: %s\n", c_str);



                printf("Return value: %s \n", PyString_AsString(pValue));
                printf("Return value length: %ld \n", PyString_Size(pValue));
                result = new char[PyString_Size(pValue) + 1];
                strcpy(result, PyString_AsString(pValue));
//                result = PyString_AsString(pValue);
                Py_DECREF(pValue);
            } else {
                Py_DECREF(pFunc);
                Py_DECREF(pModule);
                PyErr_Print();
                fprintf(stderr,"Call failed\n");
            }
        } else {
            if (PyErr_Occurred())
                PyErr_Print();
            fprintf(stderr, "Cannot find function \"%s\"\n", funcName.c_str());
        }
        Py_XDECREF(pFunc);
        Py_DECREF(pModule);
    } else{
        PyErr_Print();
        fprintf(stderr, "Failed to load \"%s\"\n", fileName.c_str());
    }
    Py_Finalize();
    return result;
}

