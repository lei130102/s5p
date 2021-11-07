#ifndef SESSION_LOCAL_PROXY_H
#define SESSION_LOCAL_PROXY_H

#include <boost/asio/io_service.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <memory>

//通过in_socket套接字read_handshake
//通过in_socket套接字write_handshake
//通过in_socket套接字read_request
//	do_remote_proxy_connect
//	write_remote_proxy_request (发送前加密sock5请求)
//	read_remote_proxy_response (接收后解密sock5响应)
//通过in_socket套接字write_response_from_remote_proxy
//do_read(2,...) 从远程代理读取的信息需要解密
//do_write(2,...) 向远程代理写入的信息需要加密

//------>| proxy |<--()--   1  read  2
//<------| proxy |---()->   2  write 1

class session_local_proxy : public std::enable_shared_from_this<session_local_proxy>
{
public:
    static std::shared_ptr<session_local_proxy> create(
            boost::asio::io_service& ioc_log
            , boost::asio::strand<boost::asio::io_service::executor_type>& strand_log
            , boost::asio::io_service& ioc
            , std::shared_ptr<boost::asio::ip::tcp::socket> socket
            , unsigned session_id
            , std::string const& remote_proxy_host
            , short remote_proxy_port
            , short verbose
            );

    ~session_local_proxy();

    void start();

private:
    session_local_proxy(
            boost::asio::io_service& ioc_log
            , boost::asio::strand<boost::asio::io_service::executor_type>& strand_log
            , boost::asio::io_service& ioc
            , std::shared_ptr<boost::asio::ip::tcp::socket> socket
            , unsigned session_id
            , std::string const& remote_proxy_host
            , short remote_proxy_port
            , short verbose
            );

    void deadline_inside_overtime(
        boost::system::error_code error
        );
    void deadline_inside_handshake_overtime(
        boost::system::error_code error
        );
    void deadline_inside_request_overtime(
        boost::system::error_code error
        );
    void deadline_inside_wallside_read_overtime(
        boost::system::error_code error
        );

    void read_handshake();

    std::size_t completion_condition_read_handshake(
            std::shared_ptr<std::array<char, 1024>> buf
            , boost::system::error_code error
            , std::size_t bytes_transferred
            );

    void handler_read_handshake_completed(
            std::shared_ptr<std::array<char, 1024>> buf
            , boost::system::error_code error
            , std::size_t bytes_transferred
            );

    void write_handshake();

    void handler_write_handshake_completed(
            boost::system::error_code error
            , std::size_t bytes_transferred
            );

    void write_refuse_handshake();

    void handler_write_refuse_handshake_completed(
            boost::system::error_code error
            , std::size_t bytes_transferred
            );

    void read_request();

    std::size_t completion_condition_read_request(
            std::shared_ptr<std::vector<char>> buf
            , boost::system::error_code error
            , std::size_t bytes_transferred
            );

    void handler_read_request_completed(
            std::shared_ptr<std::vector<char>> buf
            , boost::system::error_code error
            , std::size_t bytes_transferred
            );

    void do_remote_proxy_connect(
            std::shared_ptr<std::vector<char>> buf
            );

    void handler_remote_proxy_connect_completed(
            std::shared_ptr<std::vector<char>> buf
            , boost::system::error_code ec
            );

    void write_remote_proxy_request(
            std::shared_ptr<std::vector<char>> buf
            );

    void handler_write_remote_proxy_request_completed(
                std::shared_ptr<std::vector<char>> buf
                , boost::system::error_code error
                , std::size_t bytes_transferred
            );

    void read_remote_proxy_response();

    std::size_t completion_condition_read_remote_proxy_response(
            std::shared_ptr<std::vector<char>> buf
            , boost::system::error_code const& error
            , std::size_t bytes_transferred
            );

    void handler_read_remote_proxy_response_completed(
            std::shared_ptr<std::vector<char>> buf
            , boost::system::error_code const& error
            , std::size_t bytes_transferred
            );

    void write_response_from_remote_proxy(
            std::shared_ptr<std::vector<char>> buf
            );

    void handler_write_response_from_remote_proxy_completed(
            boost::system::error_code error
            , std::size_t bytes_transferred
            );

    void write_response();

    void handler_write_response_completed(
            boost::system::error_code error
            , std::size_t bytes_transferred
            );

    void do_read_inside();

    void handler_do_read_inside_completed(
            std::shared_ptr<std::vector<char>> buf
            , boost::system::error_code error
            , std::size_t bytes_transferred
            );

    void do_write_wallside(
            std::shared_ptr<std::vector<char>> buf
            );

    void handler_do_write_wallside_completed(
            std::shared_ptr<std::vector<char>> buf
            , boost::system::error_code error
            , std::size_t bytes_transferred
            );

    void do_read_wallside();

    void handler_do_read_wallside_completed(
            std::shared_ptr<std::vector<char>> buf
            , boost::system::error_code error
            , std::size_t bytes_transferred
            );

    void do_write_inside(
            std::shared_ptr<std::vector<char>> buf
            );

    void handler_do_write_inside_completed(
            std::shared_ptr<std::vector<char>> buf
            , boost::system::error_code error
            , std::size_t bytes_transferred
            );

private:
    boost::asio::io_service& ioc_log_;
    boost::asio::strand<boost::asio::io_service::executor_type>& strand_log_;

    boost::asio::io_service& ioc_;

    boost::asio::strand<boost::asio::io_service::executor_type> strand_;
    boost::asio::strand<boost::asio::io_service::executor_type> strand_inside_read_;
    boost::asio::strand<boost::asio::io_service::executor_type> strand_inside_write_;
    boost::asio::strand<boost::asio::io_service::executor_type> strand_wallside_read_;
    boost::asio::strand<boost::asio::io_service::executor_type> strand_wallside_write_;

    std::shared_ptr<boost::asio::ip::tcp::socket> socket_inside_;
    std::shared_ptr<boost::asio::ip::tcp::socket> socket_wallside_;

    boost::asio::deadline_timer dealline_establish_;
    boost::asio::deadline_timer deadline_inside_handshake_;
    boost::asio::deadline_timer deadline_inside_request_;
    boost::asio::deadline_timer deadline_inside_read_;
    boost::asio::deadline_timer deadline_wallside_read_;

    //远方代理的地址
    std::string remote_proxy_host_;
    short remote_proxy_port_;

    //请求的地址
    char remote_host_atyp_;
    std::vector<char> remote_host_bndaddr_;
    std::vector<char> remote_port_bndport_;

    short verbose_;

    int deadline_second_;//达成过程单阶段超时时间
    int dealline_establish_second_;//达成的超时时间，注意要比达成过程单阶段超时时间长
    int deadline_read_second_;//达成后，等待读的超时时间

    int session_id_;
};

#endif // SESSION_LOCAL_PROXY_H
