#ifndef LOG_H
#define LOG_H

#include <boost/asio/io_service.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/bind_executor.hpp>

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
    std::cerr << std::endl;
}

inline void write_log(boost::asio::io_service& ioc_log, boost::asio::strand<boost::asio::io_service::executor_type>& strand_log
    , log_level level, short verbose, int session_id, const std::string& what, const std::string& error_message = "")
{
    boost::asio::dispatch(
        ioc_log
        , boost::asio::bind_executor(strand_log
            , [session_id, verbose, what, error_message]() {
                write_log(log_level_info, verbose, session_id, what, error_message);
            }
    ));
}

#endif // LOG_H
