//
// Created by shihab on 3/16/20.
//

#ifndef CACHING_LRUCACHE_H
#define CACHING_LRUCACHE_H

#include <iostream>
#include <map>
#include <vector>
#include <string>
using namespace std;

class Node {
    string key;
    vector<string> value_vector;
public:
    Node *prev, *next;
    Node(string key, string value);
    vector<string> get_vector();
    string get_vector_string();
    int get_vector_size();
    void set_value(string value);
    string get_key();
    void set_key(string key);
};

class DoublyLinkedList {
    Node *front, *rear;
public:
    DoublyLinkedList();
    bool isEmpty();
    Node* add_page_to_head(string key, string value);
    void move_page_to_head(Node *page);
    void remove_rear_page();
    Node* get_rear_page();
};

class LRUCache {
    int capacity, size;
    DoublyLinkedList *pageList;
    map<string, Node*> pageMap;
public:
    LRUCache(int capacity);
    bool isKeyPresent(string key);
    string get(string key);
    void put(string key, string value);
    string getKeys();
    ~LRUCache();
};


#endif //CACHING_LRUCACHE_H
