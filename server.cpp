#include "server.h"

#include "log.h"
#include "session_local_proxy.h"
#include "session_remote_proxy.h"

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/bind.hpp>
#include <boost/asio.hpp>

#include <cstdlib>
#include <string>
#include <memory>
#include <utility>
#include <fstream>
#include <map>
#include <string>
#include <sstream>
#include <thread>

server::server(
        boost::asio::io_service& ioc_log
        , boost::asio::strand<boost::asio::io_service::executor_type>& strand_log
        , boost::asio::io_service& ioc
        , short port
        , std::string remote_ipv4
        , short remote_port
        , short verbose
      )
    :ioc_log_(ioc_log)
    , strand_log_(strand_log)
    , ioc_(ioc)
    , session_id_(0)
    , verbose_(verbose)
    , remote_ipv4_(remote_ipv4)
    , remote_port_(remote_port)
    , acceptor_inside_(ioc_)
{
    boost::asio::dispatch(
                ioc_log_
                , boost::asio::bind_executor(strand_log_, [=](){
        std::ostringstream what;
        what << "port: " << port;
        write_log(log_level_info, verbose_, session_id_, what.str());
    }));

    acceptor_inside_.open(boost::asio::ip::tcp::v4());
    acceptor_inside_.set_option(boost::asio::socket_base::reuse_address(true));
    acceptor_inside_.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port));
    acceptor_inside_.listen(boost::asio::socket_base::max_listen_connections);
}

void server::start()
{
    do_accept();
}

void server::do_accept()
{
    std::shared_ptr<boost::asio::ip::tcp::socket> socket(new boost::asio::ip::tcp::socket(ioc_));

    acceptor_inside_.async_accept(*socket, boost::bind(&server::handler_accept_completed, this, _1, socket));
}

void server::handler_accept_completed(boost::system::error_code error, std::shared_ptr<boost::asio::ip::tcp::socket> socket)
{
    if(error)
    {
        boost::asio::dispatch(
                        ioc_log_
                        , boost::asio::bind_executor(strand_log_
                                                     , [=](){
                std::ostringstream what;
                what << "handler_accept_completed error:" << error.value() << " " << error.message();
                write_log(log_level_info, verbose_, session_id_, what.str());
            }
                                                     ));

        socket->close();
    }
    else
    {
        boost::asio::dispatch(
                    ioc_log_
                    , boost::asio::bind_executor(strand_log_, [=](){
            std::ostringstream what;
            what << "remote_ipv4_:" << remote_ipv4_;
            write_log(log_level_info, verbose_, session_id_, what.str());
        }));

        if(remote_ipv4_ == "0.0.0.0")
        {
            session_remote_proxy::create(
                        ioc_log_
                        , strand_log_
                        , ioc_
                        , socket
                        , session_id_++
                        , verbose_
                        )
                    ->start();
        }
        else
        {
            session_local_proxy::create(
                        ioc_log_
                        , strand_log_
                        , ioc_
                        , socket
                        , session_id_++
                        , remote_ipv4_
                        , remote_port_
                        , verbose_
                        )
                    ->start();
        }
    }

    boost::asio::dispatch(
                ioc_log_
                , boost::asio::bind_executor(strand_log_, [=](){
        std::ostringstream what;
        what << "next accept";
        write_log(log_level_info, verbose_, session_id_, what.str());
    }));

    do_accept();
}
