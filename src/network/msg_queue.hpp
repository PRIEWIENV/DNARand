//
// Created by Blink on 2018/5/12.
//

#ifndef RAN_EXP_MSG_QUEUE_HPP
#define RAN_EXP_MSG_QUEUE_HPP
#include <iostream>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <set>


template <typename T>
class MsgQueue {

public:
    MsgQueue() = default;
    MsgQueue(const MsgQueue&) = delete;
    MsgQueue &operator= (const MsgQueue&) = delete;

    void pop(T& elem);
    bool empty() const;

    void push(const T& elem);

    void push(T& elem) ;
private:
    std::queue<T> queue_;
    std::mutex mutex_;
    std::condition_variable cond_;

};

template <typename T>
void MsgQueue<T>::pop(T& elem) {
    std::unique_lock<std::mutex> lck(mutex_);
    cond_.wait(lck, [this]() {return !queue_.empty();});
    elem = std::move(queue_.front());
    queue_.pop();
}


template <typename T>
bool MsgQueue<T>::empty() const {
    std::lock_guard<std::mutex> lck(mutex_);
    return queue_.empty();
}

template <typename T>
void MsgQueue<T>::push(const T& elem) {
    {
        std::lock_guard<std::mutex> lck(mutex_);
        queue_.push(elem);
    }
    cond_.notify_one();
}


template <typename T>
void MsgQueue<T>::push(T& elem) {
    {
        std::lock_guard<std::mutex> lck(mutex_);
        queue_.push(std::move(elem));
    }
    cond_.notify_one();
}



template <typename T>
class LRUSet {

public:
    LRUSet();
    LRUSet(const LRUSet&) = delete;
    LRUSet &operator= (const LRUSet&) = delete;

    bool empty() const;

    size_t max_size() const;

    bool lookup(const T& elem);

    bool lookup(T& elem);

    void push(const T& elem);

    void push(T& elem) ;
private:
    std::set<T> set_;
    std::mutex mutex_;
    size_t max_size_;
};

template <typename T>
LRUSet<T>::LRUSet() : max_size_(204800) {}


template <typename T>
bool LRUSet<T>::empty() const {
    std::lock_guard<std::mutex> lck(mutex_);
    return set_.empty();
}

template <typename T>
size_t LRUSet<T>::max_size() const {
    return max_size_;
}

template <typename T>
bool LRUSet<T>::lookup(const T& elem) {
    std::lock_guard<std::mutex> lck(mutex_);
    if (set_.find(elem) != set_.end())
        return true;
    if (set_.size() == max_size_) {
        set_.clear();
    }
    set_.insert(elem);
    return false;
}

template <typename T>
bool LRUSet<T>::lookup(T& elem) {
    std::lock_guard<std::mutex> lck(mutex_);
    if (set_.find(elem) != set_.end())
        return true;
    if (set_.size() == max_size_) {
        set_.clear();
    }
    set_.insert(elem);
    return false;
}




#endif //RAN_EXP_MSG_QUEUE_HPP
