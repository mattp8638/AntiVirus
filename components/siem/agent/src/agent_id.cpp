#include "agent_id.h"

#include <random>
#include <sstream>

namespace agent {

std::string GenerateEventId() {
    std::ostringstream stream;
    std::random_device device;
    std::mt19937 generator(device());
    std::uniform_int_distribution<int> dist(0, 255);
    stream << std::hex;
    for (int i = 0; i < 16; ++i) {
        stream << dist(generator);
    }
    return stream.str();
}

}  // namespace agent
