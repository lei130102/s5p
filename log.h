#ifndef LOG_H
#define LOG_H

#include <iostream>

enum log_level
{
    log_level_info
    , log_level_warning
    , log_level_error
};

inline void write_log(log_level level, short verbose, int session_id, const std::string& what, const std::string& error_message = "")
{
    std::string session = "";
    if (session_id >= 0)
    {
        session += "session(";
        session += std::to_string(session_id);
        session += "):";
    }

    switch(level)
    {
    case log_level_info:
    {
        std::cerr << "info:";
    }
        break;
    case log_level_warning:
    {
        std::cerr << "warning:";
    }
        break;
    case log_level_error:
    {
            std::cerr << "error:";
    }
        break;
    }

    std::cerr << session << what;
    if (error_message.size() > 0)
        std::cerr << ":" << error_message;
    std::cerr << "\n";
}

#endif // LOG_H
