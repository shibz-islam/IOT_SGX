//
// Created by shihab on 3/21/20.
//

#ifndef CACHING_LFUCACHE_H
#define CACHING_LFUCACHE_H

#include <iostream>
#include <map>
#include <unordered_map>
#include <vector>
#include <string>
using namespace std;


class NodeLFU {
    string key;
    string value;
public:
    NodeLFU *prev, *next;
    NodeLFU(string key, string value);
    string getKey();
    string getValue();
    void setKey(string key);
};



class DoublyLinkedListLFU {
    int size;
    NodeLFU *front, *rear;
public:
    DoublyLinkedListLFU();
    void addNode(NodeLFU *node);
    void removeNode(NodeLFU *node);
    NodeLFU* getFrontPage();
    int getSize();
};



class LFUCache {
    int capacity, size;
    unordered_map<string, NodeLFU*> pageMap;
    unordered_map<string, int> countMap;
    map<int, DoublyLinkedListLFU*> frequencyMap;
public:
    LFUCache(int capacity);
    string get(string key);
    void put(string key, string value);
    string getKeys();
    ~LFUCache();
};


#endif //CACHING_LFUCACHE_H
