//
// Created by shihab on 3/21/20.
//Credit: https://github.com/DeepakVadgama/Coding_Practice/blob/master/src/main/java/leetcode/LFUCache.java
//

#include "LFUCache.h"

/******
 * NodeLFU
 ******/
NodeLFU::NodeLFU(string key, string value) {
    this->key = key;
    this->value = value;
    prev = NULL;
    next = NULL;
}

string NodeLFU::getKey(){
    return key;
}

string NodeLFU::getValue() {
    return value;
}

void NodeLFU::setKey(string key) {
    this->key = key;
}


/******************
 * DoublyLinkedListLFU
 ******************/
DoublyLinkedListLFU::DoublyLinkedListLFU() {
    front = NULL;
    rear = NULL;
}

void DoublyLinkedListLFU::addNode(NodeLFU *node) {
    if (front == NULL) {
        front = node;
    } else {
        rear->next = node;
        node->prev = rear;
    }
    rear = node;
    size++;
}

void DoublyLinkedListLFU::removeNode(NodeLFU *node) {
    if (node->next == NULL)
        rear = node->prev;
    else
        node->next->prev = node->prev;

    if (front->getKey() == node->getKey())
        front = node->next;
    else
        node->prev->next = node->next;

    size--;
}

NodeLFU* DoublyLinkedListLFU::getFrontPage() {
    return front;
}

int DoublyLinkedListLFU::getSize() {
    return size;
}


/**********
 * LFUCache
 **********/
LFUCache::LFUCache(int capacity) {
    this->capacity = capacity;
    size = 0;
    pageMap = unordered_map<string, NodeLFU*>();
    countMap = unordered_map<string, int>();
    frequencyMap = map<int, DoublyLinkedListLFU*>();
}

string LFUCache::get(string key) {
    if(pageMap.find(key)==pageMap.end()) {
        return "-1";
    }
    NodeLFU *val = pageMap[key];
    // Move item from one frequency list to next. O(1) this time.
    int frequency = countMap[key];
    frequencyMap[frequency]->removeNode(val);
    // remove from map if list is empty
    if(frequencyMap[frequency]->getSize()==0)
        frequencyMap.erase(frequency);

    countMap[key] = frequency + 1;
    // add new entry in frequencyMap
    if(frequencyMap.find(frequency+1) == frequencyMap.end()) {
        frequencyMap[frequency+1] = new DoublyLinkedListLFU();
    }
    frequencyMap[frequency+1]->addNode(val);

    return val->getValue();
}

void LFUCache::put(string key, string value) {
    if(pageMap.find(key)==pageMap.end()) {
        NodeLFU *node = new NodeLFU(key, value);

        if(pageMap.size() == this->capacity){
            int lowestCount = frequencyMap.cbegin()->first;
            NodeLFU *nodeToDelete = frequencyMap[lowestCount]->getFrontPage();
            frequencyMap[lowestCount]->removeNode(nodeToDelete);
            // remove from map if list is empty
            if(frequencyMap[lowestCount]->getSize()==0)
                frequencyMap.erase(lowestCount);

            pageMap.erase(nodeToDelete->getKey());
            countMap.erase(nodeToDelete->getKey());
        }

        pageMap[key] = node;
        countMap[key] = 1;
        // add new entry in frequencyMap
        if(frequencyMap.find(1) == frequencyMap.end()) {
            frequencyMap[1] = new DoublyLinkedListLFU();
        }
        frequencyMap[1]->addNode(node);
    }
}

string LFUCache::getKeys() {
    unordered_map<string, NodeLFU*>::iterator i1;
    string key_str = "";
    for(i1=pageMap.begin();i1!=pageMap.end();i1++) {
        key_str += i1->first;
        if(i1!=pageMap.end())
            key_str+=";";
    }
    return key_str;
}

LFUCache::~LFUCache() {
    unordered_map<string, NodeLFU*>::iterator i1;
    for(i1=pageMap.begin();i1!=pageMap.end();i1++) {
        delete i1->second;
    }
}