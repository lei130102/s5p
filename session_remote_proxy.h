#ifndef SESSION_REMOTE_PROXY_H
#define SESSION_REMOTE_PROXY_H

#include <boost/asio/io_service.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <memory>
#include <thread>
#include <mutex>

//remote proxy:
//通过in_socket套接字read_request_protocol();  (接收后解密sock5请求)   对应write_remote_proxy_request
//	do_resolve
//	do_connect
//通过in_socket套接字write_response (发送前加密sock5响应)
//do_read(1,...) 从本地代理读取的信息需要解密
//do_write(1,...) 向本地代理写入的信息需要加密

//---()->| proxy |<------   1  read  2
//<--()--| proxy |------>   2  write 1
class session_remote_proxy : public std::enable_shared_from_this<session_remote_proxy>
{
public:
    static std::shared_ptr<session_remote_proxy> create(
            boost::asio::io_service& ioc_log
            , boost::asio::strand<boost::asio::io_service::executor_type>& strand_log
            , boost::asio::io_service& ioc
            , std::shared_ptr<boost::asio::ip::tcp::socket> socket
            , short remote_proxy_port
            , unsigned session_id
            , short verbose
            );

    ~session_remote_proxy();

    void start();

private:
    session_remote_proxy(
            boost::asio::io_service& ioc_log
            , boost::asio::strand<boost::asio::io_service::executor_type>& strand_log
            , boost::asio::io_service& ioc
            , std::shared_ptr<boost::asio::ip::tcp::socket> socket
            , short remote_proxy_port
            , unsigned session_id
            , short verbose
            );

    void deadline_wallside_overtime(
            boost::system::error_code error
            );
    void deadline_inside_wallside_overtime(
            boost::system::error_code error
            );

    void read_request_protocol();

    std::size_t completion_condition_read_request_protocol(
            std::shared_ptr<std::vector<char>> buf
            , boost::system::error_code error
            , std::size_t bytes_transferred
            );

    void handler_read_request_protocol_completed(
            std::shared_ptr<std::vector<char>> buf
            , boost::system::error_code error
            , std::size_t bytes_transferred
            );

    void do_resolve(
            std::string const& remote_host
            , std::string const& remote_port);

    void handler_do_resolve_completed(
            boost::system::error_code error
            , boost::asio::ip::tcp::resolver::results_type results
            );

    void do_connect(
            boost::asio::ip::tcp::resolver::results_type results
            );

    void handler_do_connect_completed(
            std::shared_ptr<boost::asio::ip::tcp::socket> socket
            , boost::system::error_code error
            );

    void write_response();

    void handler_write_response_completed(
            std::shared_ptr<std::vector<char>> buf
            , boost::system::error_code error
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

    boost::asio::ip::tcp::resolver resolver_;

    std::shared_ptr<boost::asio::ip::tcp::socket> socket_inside_;
    std::shared_ptr<boost::asio::ip::tcp::socket> socket_wallside_;

    boost::asio::deadline_timer dealline_establish_;
    boost::asio::deadline_timer deadline_inside_wallside_;

    //远程代理端口
    short remote_proxy_port_;

    //请求的地址
    char remote_host_atyp_;
    std::vector<char> remote_host_bndaddr_;
    std::vector<char> remote_port_bndport_;

    short verbose_;

    int dealline_establish_second_;
    int deadline_inside_wallside_second_;

    int session_id_;

    std::recursive_mutex inside_wallside_mutex;
};

#endif // SESSION_REMOTE_PROXY_H
