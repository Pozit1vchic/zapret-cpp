#pragma once

#include <cstdint>
#include <unordered_map>
#include <vector>

namespace zc {

struct FlowKey {
    std::uint8_t  src[16] = {};
    std::uint8_t  dst[16] = {};
    std::uint16_t sport = 0;
    std::uint16_t dport = 0;
    std::uint8_t  proto = 0;

    bool operator==(const FlowKey& o) const {
        if (sport != o.sport || dport != o.dport || proto != o.proto) {
            return false;
        }
        for (int i = 0; i < 16; ++i) {
            if (src[i] != o.src[i] || dst[i] != o.dst[i]) {
                return false;
            }
        }
        return true;
    }
};

struct FlowKeyHash {
    std::size_t operator()(const FlowKey& k) const {
        std::size_t h = 1469598103934665603ull;
        auto mix = [&h](std::uint64_t v) {
            h ^= static_cast<std::size_t>(v);
            h *= 1099511628211ull;
        };
        for (int i = 0; i < 16; i += 4) {
            std::uint32_t w = (static_cast<std::uint32_t>(k.src[i]) << 24) |
                              (static_cast<std::uint32_t>(k.src[i + 1]) << 16) |
                              (static_cast<std::uint32_t>(k.src[i + 2]) << 8) |
                              static_cast<std::uint32_t>(k.src[i + 3]);
            mix(w);
        }
        for (int i = 0; i < 16; i += 4) {
            std::uint32_t w = (static_cast<std::uint32_t>(k.dst[i]) << 24) |
                              (static_cast<std::uint32_t>(k.dst[i + 1]) << 16) |
                              (static_cast<std::uint32_t>(k.dst[i + 2]) << 8) |
                              static_cast<std::uint32_t>(k.dst[i + 3]);
            mix(w);
        }
        mix(k.sport);
        mix(k.dport);
        mix(k.proto);
        return h;
    }
};

class FlowCache {
public:
    explicit FlowCache(std::size_t capacity = 8192) : capacity_(capacity) {}

    bool seen_and_mark(const FlowKey& k, std::uint64_t now_ms);

    void prune(std::uint64_t now_ms);

    std::size_t size() const { return table_.size(); }

private:
    std::size_t capacity_;
    std::unordered_map<FlowKey, std::uint64_t, FlowKeyHash> table_;
};

}
