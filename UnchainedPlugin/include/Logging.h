#pragma once

#define MAX_LOG_FILE_SIZE 10485760

#define DEBUG +1
#define TRACE +2

#include <fstream>
#include <loguru/loguru.hpp>

void ConfigureLogging() {
    std::ifstream file("unchained-plugin.log");
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    if (size > MAX_LOG_FILE_SIZE) {
        auto result = std::rename("unchained-plugin.log", "unchained-plugin.log.1");
    }

    loguru::add_file("unchained-plugin.log", loguru::Append, loguru::Verbosity_INFO);
}