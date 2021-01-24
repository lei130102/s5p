#ifndef S5P_H
#define S5P_H

#include <boost/asio.hpp>

#include <iostream>
#include <fstream>
#include <regex>
#include <thread>
#include <string>
#include <mutex>

using boost::asio::ip::tcp;

// Common log function
/////////////////////
/// \brief write_log
/// \param prefix
//					0 信息
//					1 错误
//					2 警告
/// \param verbose
/// \param verbose_level
/// \param session_id
/// \param what
/// \param error_message
///
inline void write_log(int prefix, short verbose, short verbose_level, int session_id, const std::string& what, const std::string& error_message = "")
{
    if (verbose > verbose_level) return;

    std::string session = "";
    if (session_id >= 0) { session += "session("; session += std::to_string(session_id); session += "): "; }

    if (prefix > 0)
    {
        std::cerr << (prefix == 1 ? "Error: " : "Warning: ") << session << what;
        if (error_message.size() > 0)
            std::cerr << ": " << error_message;
        std::cerr << std::endl;
    }
    else
    {
        std::cout << session << what;
        if (error_message.size() > 0)
            std::cout << ": " << error_message;
        std::cout << std::endl;
    }
}

class Session : public std::enable_shared_from_this<Session>
{
public:
    static std::shared_ptr<Session> create(boost::asio::io_service& ioc, tcp::socket in_socket, unsigned session_id, size_t buffer_size, short verbose, std::string remote_proxy_ipv4, short remote_proxy_port);

    ~Session();

    void start();

    void remote_proxy_start();

private:
    Session(boost::asio::io_service& ioc, tcp::socket in_socket, unsigned session_id, size_t buffer_size, short verbose,  std::string remote_proxy_ipv4, short remote_proxy_port);

    void check_in_deadline();
    void check_out_deadline();

    //local proxy:
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

    //remote proxy:
    //通过in_socket套接字read_request_protocol();  (接收后解密sock5请求)   对应write_remote_proxy_request
    //	do_resolve
    //	do_connect
    //通过in_socket套接字write_response (发送前加密sock5响应)
    //do_read(1,...) 从本地代理读取的信息需要解密
    //do_write(1,...) 向本地代理写入的信息需要加密

    //---()->| proxy |<------   1  read  2
    //<--()--| proxy |------>   2  write 1

    void read_handshake();

    void write_handshake();

    void read_request();
    void read_request_protocol();

    ////

    void do_resolve();

    void do_connect(tcp::resolver::iterator& it);

    void write_response();

    ////

    void do_remote_proxy_connect();

    void write_remote_proxy_request();

    void read_remote_proxy_response();

    void write_response_from_remote_proxy();

    /////////////////

    void do_read(int protocol, int direction);

    void do_write(int protocol, int direction, std::shared_ptr<std::vector<char>> write_buf);

    /////////////////

    std::vector<char> encodeSock5Request(const std::vector<char>& request);

    std::vector<char> decodeSock5Request(const std::vector<char>& request);

    std::vector<char> encodeSock5Response(const std::vector<char>& response);

    std::vector<char> decodeSock5Response(const std::vector<char>& response);

    std::vector<char> encodeInfo(std::vector<char> info);

    std::vector<char> decodeInfo(std::vector<char> info);

    std::vector<char> encode(std::vector<char> v);
    std::vector<char> decode(std::vector<char> v);

    tcp::socket in_socket_;
    std::mutex in_socket_mutex_;
    boost::asio::deadline_timer in_deadline_;
    std::mutex in_deadline_mutex_;

    tcp::socket out_socket_;
    std::mutex out_socket_mutex_;
    boost::asio::deadline_timer out_deadline_;
    std::mutex out_deadline_mutex_;

    tcp::resolver resolver;
    std::mutex resolver_mutex_;

    int deadlineSecond_;

    size_t buffer_size_;

    std::string remote_host_;
    std::string remote_port_;
    std::vector<char> in_buf_;
    std::vector<char> out_buf_;
    std::vector<char> request_buf_;
    int session_id_;
    short verbose_;

    std::string remote_proxy_ipv4_;
    short remote_proxy_port_;
};

class Server
{
public:
    Server(boost::asio::io_service& ioc, short port, unsigned buffer_size, short verbose,std::string remote_inpv4,short remote_port);

private:
    void do_accept();

    boost::asio::io_service& ioc_;

    tcp::acceptor acceptor_;
    tcp::socket in_socket_;
    size_t buffer_size_;
    short verbose_;
    unsigned session_id_;

    std::string remote_ipv4_;
    short remote_port_;
};

#endif // S5P_H
