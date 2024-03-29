#ifndef SERVER_H
#define SERVER_H

#include <boost/asio/io_service.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/ip/tcp.hpp>

class server
{
public:
    server(
            boost::asio::io_service& ioc_log
            , boost::asio::strand<boost::asio::io_service::executor_type>& strand_log
            , boost::asio::io_service& ioc
            , short port
            , std::string remote_inpv4
            , short remote_port
            , short verbose
          );

    void start();

private:
    void do_accept();

    void handler_accept_completed(boost::system::error_code ec, std::shared_ptr<boost::asio::ip::tcp::socket> socket);

    boost::asio::io_service& ioc_log_;
    boost::asio::strand<boost::asio::io_service::executor_type>& strand_log_;

    boost::asio::io_service& ioc_;

    boost::asio::ip::tcp::acceptor acceptor_inside_;

    unsigned session_id_;
    short verbose_;
    std::string remote_ipv4_;
    short remote_port_;

    //本地代理的端口
    short local_port_;
};

#endif // SERVER_H
