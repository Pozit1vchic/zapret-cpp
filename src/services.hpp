#pragma once

#include <string>
#include <vector>

#include "desync.hpp"

namespace zc {

struct Service {
    const char* name;
    const char* suffixes[10];
    Strategy    strategy;
    int         split_pos;
    int         repeats;
    bool        fooling_badseq;
};

const std::vector<Service>& services();

bool matches_service(const std::string& sni, const Service& s);

const Service* find_service(const std::string& sni);

void apply_service(const Service& s, Config& cfg);

}
