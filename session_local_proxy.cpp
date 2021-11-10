#include "session_local_proxy.h"

#include "log.h"
#include "encode.h"

#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include<iomanip>  

std::shared_ptr<session_local_proxy> session_local_proxy::create(
        boost::asio::io_service& ioc_log
        , boost::asio::strand<boost::asio::io_service::executor_type>& strand_log
        , boost::asio::io_service& ioc
        , std::shared_ptr<boost::asio::ip::tcp::socket> socket
        , unsigned session_id
        , std::string const& remote_proxy_host
        , short remote_proxy_port
        , short local_proxy_port
        , short verbose
        )
{
    return std::shared_ptr<session_local_proxy>(new session_local_proxy(
                                                    ioc_log
                                                    , strand_log
                                                    , ioc
                                                    , socket
                                                    , session_id
                                                    , remote_proxy_host
                                                    , remote_proxy_port
                                                    , local_proxy_port
                                                    , verbose
                                                    ));
}

session_local_proxy::session_local_proxy(
        boost::asio::io_service& ioc_log
        , boost::asio::strand<boost::asio::io_service::executor_type>& strand_log
        , boost::asio::io_service& ioc
        , std::shared_ptr<boost::asio::ip::tcp::socket> socket
        , unsigned session_id
        , std::string const& remote_proxy_host
        , short remote_proxy_port
        , short local_proxy_port
        , short verbose
        )
    :ioc_log_(ioc_log)
    , strand_log_(strand_log)
    , ioc_(ioc)
    , socket_inside_(socket)
    , dealline_establish_(ioc)
    , deadline_inside_handshake_(ioc)
    , deadline_inside_request_(ioc)
    , deadline_inside_wallside_(ioc)
    , socket_wallside_(new boost::asio::ip::tcp::socket(ioc))
    , session_id_(session_id)
    , remote_proxy_host_(remote_proxy_host)
    , remote_proxy_port_(remote_proxy_port)
    , local_proxy_port_(local_proxy_port)
    , remote_host_atyp_('\0')
    , verbose_(verbose)
    , deadline_second_(10)
    , dealline_establish_second_(12)
    , deadline_inside_wallside_second_(20)
    , strand_(boost::asio::make_strand(ioc))
    , strand_inside_read_(boost::asio::make_strand(ioc))
    , strand_inside_write_(boost::asio::make_strand(ioc))
    , strand_wallside_read_(boost::asio::make_strand(ioc))
    , strand_wallside_write_(boost::asio::make_strand(ioc))
{
    write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, "created");
}

session_local_proxy::~session_local_proxy()
{
    write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, "destroying");

    if(socket_inside_->is_open())
    {
        boost::system::error_code ec;
        socket_inside_->shutdown(boost::asio::socket_base::shutdown_both, ec);
        //注意，多个线程对同一个socket进行操作时，如果执行close那么有可能抛出异常
        try
        {
            socket_inside_->close();
        }
        catch(boost::system::error_code& ec)
        {}
    }
    if(socket_wallside_->is_open())
    {
        boost::system::error_code ec;
        socket_wallside_->shutdown(boost::asio::socket_base::shutdown_both, ec);
        //注意，多个线程对同一个socket进行操作时，如果执行close那么有可能抛出异常
        try
        {
            socket_wallside_->close();
        }
        catch(boost::system::error_code& ec)
        {}
    }

	dealline_establish_.cancel();
	deadline_inside_handshake_.cancel();
	deadline_inside_request_.cancel();
    deadline_inside_wallside_.cancel();

    write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, "destroyed");
}

void session_local_proxy::deadline_inside_overtime(
        boost::system::error_code error
        )
{
    if(error)
    {
        return;
    }

    write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, "deadline_inside_overtime");

    boost::system::error_code ec;
    socket_inside_->shutdown(boost::asio::socket_base::shutdown_both, ec);
    socket_wallside_->shutdown(boost::asio::socket_base::shutdown_both, ec);
}

void session_local_proxy::deadline_inside_handshake_overtime(
        boost::system::error_code error
        )
{
    if(error)
    {
        return;
    }

    dealline_establish_.cancel();//只需要有一个定时器超时就行

    write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, "deadline_inside_handshake_overtime");

    write_refuse_handshake();
}

void session_local_proxy::deadline_inside_request_overtime(
    boost::system::error_code error
    )
{
    if(error)
    {
        return;
    }

    dealline_establish_.cancel();//只需要有一个定时器超时就行

    write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, "deadline_inside_request_overtime");

    write_response();
}

void session_local_proxy::deadline_inside_wallside_overtime(
        boost::system::error_code error
        )
{
    if(error)
    {
        return;
    }

    write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, "deadline_inside_wallside_overtime");

    deadline_inside_wallside_.cancel();

    boost::system::error_code ec;
    socket_inside_->shutdown(boost::asio::socket_base::shutdown_both, ec);
    socket_wallside_->shutdown(boost::asio::socket_base::shutdown_both, ec);
}

void session_local_proxy::start()
{
    read_handshake();
}

void session_local_proxy::read_handshake()
{
    dealline_establish_.expires_from_now(boost::posix_time::seconds(dealline_establish_second_));
    dealline_establish_.async_wait(
                boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::deadline_inside_overtime, shared_from_this(), boost::placeholders::_1))
                );

    std::shared_ptr<std::array<char, 1024>> buf(new std::array<char, 1024>{});
    boost::asio::async_read(
                *socket_inside_
                , boost::asio::buffer(*buf)
                , boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::completion_condition_read_handshake, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2))
                , boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::handler_read_handshake_completed, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2)));
}

std::size_t session_local_proxy::completion_condition_read_handshake(
        std::shared_ptr<std::array<char, 1024>> buf
        , boost::system::error_code error
        , std::size_t bytes_transferred
        )
{
/*
The client connects to the server, and sends a version
identifier/method selection message:
+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+
The values currently defined for METHOD are:
o  X'00' NO AUTHENTICATION REQUIRED
o  X'01' GSSAPI
o  X'02' USERNAME/PASSWORD
o  X'03' to X'7F' IANA ASSIGNED
o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
o  X'FF' NO ACCEPTABLE METHODS
*/

    if(error)
    {
        return 0;
    }

    if(bytes_transferred < 2)
    {
        return 1;
    }

    if(buf->at(0) != 0x05)
    {
        return 1;
    }

    std::size_t size = buf->at(1);
    if(bytes_transferred < size + 2)
    {
        return 1;
    }

    return 0;
}

void session_local_proxy::handler_read_handshake_completed(
        std::shared_ptr<std::array<char, 1024>> buf
        , boost::system::error_code error
        , std::size_t bytes_transferred
        )
{
    if(error)
    {
        boost::system::error_code ec;
        socket_inside_->shutdown(boost::asio::socket_base::shutdown_both, ec);

        return;
    }

    write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, "read handshake");

    //收到了客户端的握手，设定时器要求必须返回握手响应
    deadline_inside_handshake_.expires_from_now(boost::posix_time::seconds(deadline_second_));
    deadline_inside_handshake_.async_wait(
                boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::deadline_inside_handshake_overtime, shared_from_this(), boost::placeholders::_1))
                );

    //收到客户端认证方式请求后直接告诉他服务器端不需要认证方式

    write_handshake();
}

void session_local_proxy::write_handshake()
{
    std::shared_ptr<std::array<char, 2>> buf(new std::array<char, 2>{});
    buf->at(0) = 0x05;
    buf->at(1) = 0x00;

    boost::asio::async_write(
                *socket_inside_
                , boost::asio::buffer(*buf, 2) // Always 2-byte according to RFC1928
                , boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::handler_write_handshake_completed, shared_from_this(), buf//注意必须要传递他，以延长buf的生命周期，使boost::asio::buffer(*buf, 2)一直有效
                    , boost::placeholders::_1, boost::placeholders::_2)));
}

void session_local_proxy::handler_write_handshake_completed(
        std::shared_ptr<std::array<char, 2>> buf
        , boost::system::error_code error
        , std::size_t bytes_transferred
        )
{
    if(error)
    {
        boost::system::error_code ec;
        socket_inside_->shutdown(boost::asio::socket_base::shutdown_both, ec);
        return;
    }

    write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, "write handshake");

    deadline_inside_handshake_.cancel();

    read_request();
}

void session_local_proxy::write_refuse_handshake()
{
    std::shared_ptr<std::array<char, 2>> buf(new std::array<char, 2>{});
    buf->at(0) = 0x05;
    buf->at(1) = 0xFF;

    boost::asio::async_write(
                *socket_inside_
                , boost::asio::buffer(*buf, 2) // Always 2-byte according to RFC1928
                , boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::handler_write_refuse_handshake_completed, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2)));
}

void session_local_proxy::handler_write_refuse_handshake_completed(
        std::shared_ptr<std::array<char, 2>>
        , boost::system::error_code error
        , std::size_t bytes_transferred
        )
{
    write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, "write refuse handshake");

    boost::system::error_code ec;
    socket_inside_->shutdown(boost::asio::socket_base::shutdown_both, ec);
}

void session_local_proxy::read_request()
{
    std::shared_ptr<std::array<char, 1024>> buf(new std::array<char, 1024>{});
    boost::asio::async_read(
                    *socket_inside_
                    , boost::asio::buffer(*buf)
                    , boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::completion_condition_read_request, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2))
                    , boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::handler_read_request_completed, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2))
                );
}

std::size_t session_local_proxy::completion_condition_read_request(
        std::shared_ptr<std::array<char, 1024>> buf
        , boost::system::error_code error
        , std::size_t bytes_transferred)
{
    /*
        The SOCKS request is formed as follows:
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
        Where:
        o  VER    protocol version: X'05'
        o  CMD
        o  CONNECT X'01'
        o  BIND X'02'
        o  UDP ASSOCIATE X'03'
        o  RSV    RESERVED
        o  ATYP   address type of following address
        o  IP V4 address: X'01'
        o  DOMAINNAME: X'03'
        o  IP V6 address: X'04'
        o  DST.ADDR       desired destination address
        o  DST.PORT desired destination port_ in network octet
        order
        The SOCKS server will typically evaluate the request based on source
        and destination addresses, and return one or more reply messages, as
        appropriate for the request type.
        */

    if(error)
    {
        return 0;
    }

    //长度检查
    if(bytes_transferred < 4)
    {
        return 1;
    }
    switch (buf->at(3))
    {
    case 0x01: // IP V4 addres
        {
            if(bytes_transferred < (4 + 4 + 2))
            {
                return 1;//再读1个字节
            }
        }
        break;
    case 0x03: // DOMAINNAME
        {
            if(bytes_transferred < 5)
            {
                return 1;//再读1个字节
            }

            if(bytes_transferred < (4 + 1 + (std::size_t)(buf->at(4)) + 2))
            {
                return 1;//再读1个字节
            }
        }
        break;
    case 0x04: // IP V6 addres
        {
            if(bytes_transferred < (4 + 16 + 2))
            {
                return 1;
            }
        }
        break;
    }

    //值检查
    if(buf->at(0) != 0x05)
    {
        return 1;
    }

    if(buf->at(1) != 0x01)
    {
        return 1;
    }

    return 0;
}

void session_local_proxy::handler_read_request_completed(
        std::shared_ptr<std::array<char, 1024>> buf
        , boost::system::error_code error
        , std::size_t bytes_transferred)
{
    if(error)
    {
        boost::system::error_code ec;
        socket_inside_->shutdown(boost::asio::socket_base::shutdown_both, ec);
        return;
    }

    std::shared_ptr<std::vector<char>> buf_read(new std::vector<char>(buf->begin(), buf->begin() + bytes_transferred));

//    {
//		std::stringstream ss;
//        ss << "local_proxy_request:";
//        for (auto element : *buf_read)
//        {
//            ss << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)(*(unsigned char*)&element) << " ";
//        }
//        std::string what = ss.str();
//	    write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, what);
//    }

    //收到了客户端的请求，设定时器要求必须返回请求响应
    deadline_inside_request_.expires_from_now(boost::posix_time::seconds(deadline_second_));
    deadline_inside_request_.async_wait(
                boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::deadline_inside_request_overtime, shared_from_this(), boost::placeholders::_1))
                );

    do_remote_proxy_connect(buf_read);

    remote_host_atyp_ = buf_read->at(3);

    switch (buf_read->at(3))
    {
    case 0x01: // IP V4 addres
        {

            std::copy(buf_read->begin() + 4, buf_read->begin() + 4 + 4, std::back_inserter(remote_host_bndaddr_));
            std::copy(buf_read->begin() + 4 + 4, buf_read->begin() + 4 + 4 + 2, std::back_inserter(remote_port_bndport_));

            do_remote_proxy_connect(buf_read);

        }
        break;
    case 0x03: // DOMAINNAME
        {
            uint8_t host_length = buf_read->at(4);

            std::copy(buf_read->begin() + 4, buf_read->begin() + 4 + 1 + host_length, std::back_inserter(remote_host_bndaddr_));
            std::copy(buf_read->begin() + 4 + 1 + host_length, buf_read->begin() + 4 + 1 + host_length + 2, std::back_inserter(remote_port_bndport_));

            do_remote_proxy_connect(buf_read);

        }
        break;
    case 0x04: // IP V6 addres
        {
            std::copy(buf_read->begin() + 4, buf_read->begin() + 4 + 16, std::back_inserter(remote_host_bndaddr_));
            std::copy(buf_read->begin() + 4 + 16, buf_read->begin() + 4 + 16 + 2, std::back_inserter(remote_port_bndport_));

            do_remote_proxy_connect(buf_read);
        }
        break;
    }
}

void session_local_proxy::do_remote_proxy_connect(
        std::shared_ptr<std::vector<char>> buf
        )
{
    std::shared_ptr<std::vector<char>> buf_connect(new std::vector<char>(*buf));

    boost::asio::ip::tcp::endpoint ep(boost::asio::ip::address::from_string(remote_proxy_host_), remote_proxy_port_);

    socket_wallside_->async_connect(
                ep
                , boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::handler_remote_proxy_connect_completed, shared_from_this(), buf_connect, boost::placeholders::_1)));
}

void session_local_proxy::handler_remote_proxy_connect_completed(
        std::shared_ptr<std::vector<char>> buf
        , boost::system::error_code error
        )
{
    if(error)
    {
        return;
    }

    std::shared_ptr<std::vector<char>> buf_connect(new std::vector<char>(*buf));

    write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, "remote proxy connected");

    write_remote_proxy_request(buf_connect);
}

void session_local_proxy::write_remote_proxy_request(
        std::shared_ptr<std::vector<char>> buf
        )
{
    std::shared_ptr<std::vector<char>> buf_encode(new std::vector<char>(buf->size()));
    encode(buf->begin(), buf->end(), buf_encode->begin());

    boost::asio::async_write(
                *socket_wallside_
                , boost::asio::buffer(*buf_encode)
                , boost::asio::transfer_at_least(buf_encode->size())
                , boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::handler_write_remote_proxy_request_completed, shared_from_this(), buf_encode, boost::placeholders::_1, boost::placeholders::_2))
                );
}

void session_local_proxy::handler_write_remote_proxy_request_completed(
        std::shared_ptr<std::vector<char>> buf
        , boost::system::error_code error
        , std::size_t bytes_transferred
        )
{
    if(error)
    {
        return;
    }

    read_remote_proxy_response();
}

void session_local_proxy::read_remote_proxy_response()
{
    std::shared_ptr<std::array<char, 1024>> buf(new std::array<char, 1024>{});
    boost::asio::async_read(
                    *socket_wallside_
                    , boost::asio::buffer(*buf)
                    , boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::completion_condition_read_remote_proxy_response, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2))
                    , boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::handler_read_remote_proxy_response_completed, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2))
                );
}

std::size_t session_local_proxy::completion_condition_read_remote_proxy_response(
        std::shared_ptr<std::array<char, 1024>> buf
        , boost::system::error_code const& error
        , std::size_t bytes_transferred
        )
{
    if(error)
    {
		std::ostringstream what;
		what << "completion_condition_read_remote_proxy_response error:" << error.value() << " " << error.message();
        write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, what.str());

        return 0;
    }

    std::shared_ptr<std::vector<char>> buf_decode(new std::vector<char>(bytes_transferred));
    decode(buf->begin(), buf->begin() + bytes_transferred, buf_decode->begin());

    //长度检查
    if(bytes_transferred < 4)
    {
        return 1;
    }

    switch (buf_decode->at(3))
    {
        case 0x01:
        {
            if(bytes_transferred < (4 + 4 + 2))
            {
                return 1;
            }
        }
        break;
        case 0x03:
        {
            if(bytes_transferred < 5)
            {
                return 1;
            }

            if(bytes_transferred < (4 + 1 + (std::size_t)(buf_decode->at(4)) + 2))
            {
                return 1;
            }
        }
        break;
        case 0x04:
        {
            if(bytes_transferred < (4 + 16 + 2))
            {
                return 1;
            }
        }
        break;
    }

    //值检查
    if(buf_decode->at(0) != 0x05)
    {
        return 1;
    }

    if(buf_decode->at(2) != 0x00)//保留位
    {
        return 1;
    }

    return 0;
}

void session_local_proxy::handler_read_remote_proxy_response_completed(
        std::shared_ptr<std::array<char, 1024>> buf
        , boost::system::error_code const& error
        , std::size_t bytes_transferred
        )
{
    if(error)
    {
        return;
    }

    std::shared_ptr<std::vector<char>> buf_decode(new std::vector<char>(bytes_transferred));
    decode(buf->begin(), buf->begin() + bytes_transferred, buf_decode->begin());

    {
		std::stringstream ss;
        ss << "remote_proxy_response:";
        for (auto element : *buf_decode)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)(*(unsigned char*)&element) << " ";
        }
	    write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, ss.str());
    }

    write_response_from_remote_proxy(buf_decode);
}

void session_local_proxy::write_response_from_remote_proxy(
        std::shared_ptr<std::vector<char>> buf
        )
{
    boost::asio::async_write(
                *socket_inside_
                , boost::asio::buffer(*buf)
                , boost::asio::transfer_at_least(buf->size())
                , boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::handler_write_response_from_remote_proxy_completed, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2))
                );
}

void session_local_proxy::handler_write_response_from_remote_proxy_completed(
        std::shared_ptr<std::vector<char>> buf
        , boost::system::error_code error
        , std::size_t bytes_transferred
        )
{
    if(error)
    {
        return;
    }

	write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, "write response (from remote proxy)");

    dealline_establish_.cancel();

    deadline_inside_request_.cancel();

    do_read_inside();
    do_read_wallside();
}

void session_local_proxy::write_response()
{
    std::shared_ptr<std::vector<char>> buf(new std::vector<char>);
//    {
//        //返回本地代理的ip和端口
//        boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), local_proxy_port_);

//        buf->push_back(0x05);
//        buf->push_back(0x03);//不管具体什么原因无法返回响应，都按照 0x03网络不可达 处理
//        buf->push_back(0x00);
//        buf->push_back(0x01);//本地代理的ip是ipv4
//        auto ip = ep.address().to_v4().to_bytes();
//        buf->insert(buf->end(), ip.begin(), ip.end());
//        auto port = ep.port();
//        buf->push_back(*((char*)(&port)));
//        buf->push_back(*((char*)(&port) + 1));
//    }

    {
        //返回原来的ip和端口
        buf->push_back(0x05);
        buf->push_back(0x03);//不管具体什么原因无法返回响应，都按照 0x03网络不可达 处理
        buf->push_back(0x00);
        buf->push_back(remote_host_atyp_);

        buf->insert(buf->end(), remote_host_bndaddr_.begin(), remote_host_bndaddr_.end());
        buf->insert(buf->end(), remote_port_bndport_.begin(), remote_port_bndport_.end());
    }

    char remote_host_atyp;
    std::vector<char> remote_host_bndaddr;
    std::vector<char> remote_port_bndport;

    boost::asio::async_write(
                *socket_inside_
                , boost::asio::buffer(*buf)
                , boost::asio::transfer_at_least(buf->size())
                , boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::handler_write_response_completed, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2))
                );
}

void session_local_proxy::handler_write_response_completed(
        std::shared_ptr<std::vector<char>> buf
        , boost::system::error_code error
        , std::size_t bytes_transferred
        )
{
    if (error)
    {
        return;
    }

	write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, "write refuse response (from local proxy)");

    boost::system::error_code ec;
    socket_inside_->shutdown(boost::asio::socket_base::shutdown_both, ec);
    socket_wallside_->shutdown(boost::asio::socket_base::shutdown_both, ec);
}

void session_local_proxy::do_read_inside()
{
    {
        std::lock_guard<std::recursive_mutex> lg(inside_wallside_mutex_);

        deadline_inside_wallside_.expires_from_now(boost::posix_time::seconds(deadline_inside_wallside_second_));
        deadline_inside_wallside_.async_wait(
                    boost::bind(&session_local_proxy::deadline_inside_wallside_overtime, shared_from_this(), boost::placeholders::_1)
                    );
    }

    std::shared_ptr<std::vector<char>> buf(new std::vector<char>(40960, 0));
    socket_inside_->async_read_some(
                boost::asio::buffer(*buf)
                , boost::asio::bind_executor(strand_inside_read_, boost::bind(&session_local_proxy::handler_do_read_inside_completed, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2))
                );
}

void session_local_proxy::handler_do_read_inside_completed(
        std::shared_ptr<std::vector<char>> buf
        , boost::system::error_code error
        , std::size_t bytes_transferred
        )
{
    if(error)
    {
        return;
    }

	std::ostringstream what;
	what << " --> " << std::to_string(bytes_transferred) << " bytes";
	write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, what.str());

    auto buf_write = std::make_shared<std::vector<char>>(buf->begin(), buf->begin() + bytes_transferred);

    std::shared_ptr<std::vector<char>> buf_write_encode(new std::vector<char>(buf_write->size()));
    encode(buf_write->begin(), buf_write->end(), buf_write_encode->begin());

    do_write_wallside(buf_write_encode);

    do_read_inside();
}

void session_local_proxy::do_write_wallside(
        std::shared_ptr<std::vector<char>> buf
        )
{
    {
        std::lock_guard<std::recursive_mutex> lg(inside_wallside_mutex_);

        deadline_inside_wallside_.expires_from_now(boost::posix_time::seconds(deadline_inside_wallside_second_));
        deadline_inside_wallside_.async_wait(
                    boost::bind(&session_local_proxy::deadline_inside_wallside_overtime, shared_from_this(), boost::placeholders::_1)
                    );
    }

    std::shared_ptr<std::vector<char>> buf_write(new std::vector<char>(*buf));

    socket_wallside_->async_write_some(
                boost::asio::buffer(*buf_write)
                , boost::asio::bind_executor(strand_wallside_write_, boost::bind(&session_local_proxy::handler_do_write_wallside_completed, shared_from_this(), buf_write, boost::placeholders::_1, boost::placeholders::_2))
                );
}

void session_local_proxy::handler_do_write_wallside_completed(
        std::shared_ptr<std::vector<char>> buf
        , boost::system::error_code error
        , std::size_t bytes_transferred
        )
{
    if(error)
    {
        return;
    }

    if(bytes_transferred < buf->size())
    {
        auto buf_write = std::make_shared<std::vector<char>>(buf->begin() + bytes_transferred, buf->end());
        do_write_wallside(buf_write);
    }
}

void session_local_proxy::do_read_wallside()
{
    {
        std::lock_guard<std::recursive_mutex> lg(inside_wallside_mutex_);

        deadline_inside_wallside_.expires_from_now(boost::posix_time::seconds(deadline_inside_wallside_second_));
        deadline_inside_wallside_.async_wait(
                    boost::bind(&session_local_proxy::deadline_inside_wallside_overtime, shared_from_this(), boost::placeholders::_1)
                    );
    }

    std::shared_ptr<std::vector<char>> buf(new std::vector<char>(40960, 0));
    socket_wallside_->async_read_some(
                boost::asio::buffer(*buf)
                , boost::asio::bind_executor(strand_wallside_read_, boost::bind(&session_local_proxy::handler_do_read_wallside_completed, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2))
                );
}

void session_local_proxy::handler_do_read_wallside_completed(
        std::shared_ptr<std::vector<char>> buf
        , boost::system::error_code error
        , std::size_t bytes_transferred
        )
{
    if(error)
    {
        return;
    }

	std::ostringstream what;
	what << " <-- " << std::to_string(bytes_transferred) << " bytes";
	write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, what.str());

    auto buf_write = std::make_shared<std::vector<char>>(buf->begin(), buf->begin() + bytes_transferred);

    std::shared_ptr<std::vector<char>> buf_write_decode(new std::vector<char>(buf_write->size()));
    decode(buf_write->begin(), buf_write->end(), buf_write_decode->begin());

    do_write_inside(buf_write_decode);

    do_read_wallside();
}

void session_local_proxy::do_write_inside(
        std::shared_ptr<std::vector<char>> buf
        )
{
    {
        std::lock_guard<std::recursive_mutex> lg(inside_wallside_mutex_);

        deadline_inside_wallside_.expires_from_now(boost::posix_time::seconds(deadline_inside_wallside_second_));
        deadline_inside_wallside_.async_wait(
                    boost::bind(&session_local_proxy::deadline_inside_wallside_overtime, shared_from_this(), boost::placeholders::_1)
                    );
    }

    std::shared_ptr<std::vector<char>> buf_write(new std::vector<char>(*buf));

    socket_inside_->async_write_some(
                boost::asio::buffer(*buf_write)
                , boost::asio::bind_executor(strand_inside_write_, boost::bind(&session_local_proxy::handler_do_write_inside_completed, shared_from_this(), buf_write, boost::placeholders::_1, boost::placeholders::_2))
                );
}

void session_local_proxy::handler_do_write_inside_completed(
        std::shared_ptr<std::vector<char>> buf
        , boost::system::error_code error
        , std::size_t bytes_transferred
        )
{
    if(error)
    {
        std::ostringstream what;
        what << "handler_do_write_inside_completed error:" << error.value() << " " << error.message();
        write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, what.str());

        return;
    }

    if(bytes_transferred < buf->size())
    {

        auto buf_write = std::make_shared<std::vector<char>>(buf->begin() + bytes_transferred, buf->end());
        do_write_inside(buf_write);
    }
}
