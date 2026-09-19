#pragma once

#include <string>

#include "packet.hpp"

namespace zc {

struct WdAddress {
    bool outbound = false;
    bool loopback = false;
};

class Windivert {
public:
    Windivert() = default;
    ~Windivert();

    Windivert(const Windivert&) = delete;
    Windivert& operator=(const Windivert&) = delete;

    bool open(const std::string& filter);
    void close();

    bool receive(unsigned char* buffer, unsigned int capacity, unsigned int& length,
                 WdAddress& addr);
    bool send(const unsigned char* buffer, unsigned int length, const WdAddress& addr);

    bool is_open() const { return handle_ != nullptr; }
    unsigned long last_error() const { return last_error_; }

    static std::string last_open_error();

private:
    void*         handle_ = nullptr;
    unsigned long last_error_ = 0;
};

}
