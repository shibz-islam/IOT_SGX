//
// Created by shihab on 3/16/20.
//

#include "LRUCache.h"


/*
 * Node
 */
Node::Node(string key, string value) {
    this->key = key;
    value_vector.push_back(value);
    prev = NULL;
    next = NULL;
}

vector<string> Node::get_vector() {
    return value_vector;
}

string Node::get_vector_string() {
    string value_str;
    for (int i=0;i<value_vector.size();i++)
    {
        if(i==value_vector.size()-1)
            value_str += value_vector[i];
        else
            value_str += value_vector[i] + ";";
    }
    return value_str;
}

int Node::get_vector_size() {
    return value_vector.size();
}

void Node::set_value(string value) {
    value_vector.push_back(value);
}

string Node::get_key() {
    return key;
}

void Node::set_key(string key) {
    this->key = key;
}

/*
 * DoublyLinkedList
 */
DoublyLinkedList::DoublyLinkedList() {
    front = NULL;
    rear = NULL;
}

bool DoublyLinkedList::isEmpty() {
    return rear == NULL;
}

Node* DoublyLinkedList::add_page_to_head(string key, string value) {
    Node *page = new Node(key, value);
    if(!front && !rear) {
        front = rear = page;
    }
    else {
        page->next = front;
        front->prev = page;
        front = page;
    }
    return page;
}

void DoublyLinkedList::move_page_to_head(Node *page) {
    if(page==front) {
        return;
    }
    if(page == rear) {
        rear = rear->prev;
        rear->next = NULL;
    }
    else {
        page->prev->next = page->next;
        page->next->prev = page->prev;
    }

    page->next = front;
    page->prev = NULL;
    front->prev = page;
    front = page;
}

void DoublyLinkedList::remove_rear_page() {
    if(isEmpty()) {
        return;
    }
    if(front == rear) {
        delete rear;
        front = rear = NULL;
    }
    else {
        Node *temp = rear;
        rear = rear->prev;
        rear->next = NULL;
        delete temp;
    }
}

Node* DoublyLinkedList::get_rear_page() {
    return rear;
}


/*
 * LRUCache
 */
LRUCache::LRUCache(int capacity) {
    this->capacity = capacity;
    size = 0;
    pageList = new DoublyLinkedList();
    pageMap = map<string, Node*>();
}

bool LRUCache::isKeyPresent(string key) {
    if(pageMap.find(key)==pageMap.end()) {
        return false;
    }
    return true;
}

string LRUCache::get(string key) {
    if(pageMap.find(key)==pageMap.end()) {
        return "-1";
    }
    string val = pageMap[key]->get_vector_string();

    // move the page to front
    pageList->move_page_to_head(pageMap[key]);
    return val;
}

void LRUCache::put(string key, string value) {
    if(pageMap.find(key)!=pageMap.end()) {
        // if key already present, update value and move page to head
        pageMap[key]->set_value(value);
        pageList->move_page_to_head(pageMap[key]);
        return;
    }

    if(size == capacity) {
        // remove rear page
        string k = pageList->get_rear_page()->get_key();
        pageMap.erase(k);
        pageList->remove_rear_page();
        size--;
    }

    // add new page to head to Queue
    Node *page = pageList->add_page_to_head(key, value);
    size++;
    pageMap[key] = page;
}

string LRUCache::getKeys() {
    map<string, Node*>::iterator i1;
    string key_str = "";
    for(i1=pageMap.begin();i1!=pageMap.end();i1++) {
        key_str += i1->first;
        if(i1!=pageMap.end())
            key_str+=";";
    }
    return key_str;
}

LRUCache::~LRUCache() {
    map<string, Node*>::iterator i1;
    for(i1=pageMap.begin();i1!=pageMap.end();i1++) {
        delete i1->second;
    }
    delete pageList;
}
