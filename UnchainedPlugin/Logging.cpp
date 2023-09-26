#include "include/Logging.h"

const std::string DEFAULT_CONFIG = R"(
    * GLOBAL:
        TO_STANDARD_OUTPUT   = true
        FORMAT               = "[%logger][%level] %msg"
        FILENAME             = "unchained-plugin.log"
        TO_FILE              = true
        ENABLED              = true
        MAX_LOG_FILE_SIZE    =  2097152
        LOG_FLUSH_THRESHOLD  =  10000

    * DEBUG:
        ENABLED = false
    * INFO:
        ENABLED = true
    * WARNING:
        ENABLED = true
    * ERROR:
        ENABLED = true
)";

const std::string ALTERNATE_CONFIG_PATH = "unchained-plugin.conf";

void ConfigureLogging() {
    char** emptyArgs = {};
    START_EASYLOGGINGPP(0, emptyArgs);

    el::Loggers::addFlag(el::LoggingFlag::MultiLoggerSupport);
    el::Loggers::addFlag(el::LoggingFlag::LogDetailedCrashReason);
    el::Loggers::addFlag(el::LoggingFlag::CreateLoggerAutomatically);
    el::Loggers::addFlag(el::LoggingFlag::ColoredTerminalOutput);

    std::ifstream testConfigFile(ALTERNATE_CONFIG_PATH);
    if (testConfigFile.good()) {
        el::Configurations conf(ALTERNATE_CONFIG_PATH);
        el::Loggers::reconfigureAllLoggers(conf);
        el::Loggers::setDefaultConfigurations(conf, true);
    }
    else {
        el::Configurations conf;
        conf.parseFromText(DEFAULT_CONFIG);
        el::Loggers::reconfigureAllLoggers(conf);
        el::Loggers::setDefaultConfigurations(conf, true);
    }
}