#pragma once

#include <cstdint>
#include <unordered_map>
#include <vector>

namespace zc {

struct FlowKey {
    std::uint32_t src = 0;
    std::uint32_t dst = 0;
    std::uint16_t sport = 0;
    std::uint16_t dport = 0;
    std::uint8_t  proto = 0;

    bool operator==(const FlowKey& o) const {
        return src == o.src && dst == o.dst && sport == o.sport && dport == o.dport &&
               proto == o.proto;
    }
};

struct FlowKeyHash {
    std::size_t operator()(const FlowKey& k) const {
        std::size_t h = 1469598103934665603ull;
        auto mix = [&h](std::uint64_t v) {
            h ^= static_cast<std::size_t>(v);
            h *= 1099511628211ull;
        };
        mix(k.src);
        mix(k.dst);
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
