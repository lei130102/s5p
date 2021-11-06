#include "session_local_proxy.h"

#include "log.h"
#include "encode.h"

#include <boost/asio.hpp>
#include <boost/bind.hpp>

std::shared_ptr<session_local_proxy> session_local_proxy::create(
        boost::asio::io_service& ioc
        , boost::asio::strand<boost::asio::io_service::executor_type>& strand_log
        , std::shared_ptr<boost::asio::ip::tcp::socket> socket_inside
        , unsigned session_id
        , std::string const& remote_proxy_host
        , short remote_proxy_port
        , short verbose
        )
{
    return std::shared_ptr<session_local_proxy>(new session_local_proxy(
                                                    ioc
                                                    , strand_log
                                                    , socket_inside
                                                    , session_id
                                                    , remote_proxy_host
                                                    , remote_proxy_port
                                                    , verbose
                                                    ));
}

session_local_proxy::session_local_proxy(
        boost::asio::io_service& ioc
        , boost::asio::strand<boost::asio::io_service::executor_type>& strand_log
        , std::shared_ptr<boost::asio::ip::tcp::socket> socket_inside
        , unsigned session_id
        , std::string const& remote_proxy_host
        , short remote_proxy_port
        , short verbose
        )
    :ioc_(ioc)
    , strand_log_(strand_log)
    , socket_inside_(socket_inside)
    , dealline_establish_(ioc)
    , deadline_inside_handshake_(ioc)
    , deadline_inside_request_(ioc)
    , deadline_inside_read_(ioc)
    , deadline_wallside_read_(ioc)
    , socket_wallside_(new boost::asio::ip::tcp::socket(ioc))
    , session_id_(session_id)
    , remote_proxy_host_(remote_proxy_host)
    , remote_proxy_port_(remote_proxy_port)
    , remote_host_atyp_('\0')
    , verbose_(verbose)
    , deadline_second_(5)
    , dealline_establish_second_(10)
    , deadline_read_second_(600)
    , strand_(boost::asio::make_strand(ioc))
    , strand_inside_read_(boost::asio::make_strand(ioc))
    , strand_inside_write_(boost::asio::make_strand(ioc))
    , strand_wallside_read_(boost::asio::make_strand(ioc))
    , strand_wallside_write_(boost::asio::make_strand(ioc))
{}

session_local_proxy::~session_local_proxy()
{
    boost::asio::dispatch(
                ioc_
                , boost::asio::bind_executor(strand_log_, [&](){
        std::ostringstream what;
        what << "session " << session_id_ << " destroyed";
        write_log(log_level_info, verbose_, session_id_, what.str());
    }));

    if(socket_inside_->is_open())
    {
        socket_inside_->close();
    }
    if(socket_wallside_->is_open())
    {
        socket_wallside_->close();
    }

    dealline_establish_.cancel();
    deadline_inside_handshake_.cancel();
    deadline_inside_request_.cancel();
    deadline_inside_read_.cancel();
    deadline_wallside_read_.cancel();
}

void session_local_proxy::deadline_inside_overtime(
        boost::system::error_code error
        )
{
    if(error)
    {
        return;
    }

    boost::asio::dispatch(
                    ioc_
                    , boost::asio::bind_executor(strand_log_, [&](){
            std::ostringstream what;
            what << " deadline_inside_overtime ";
            write_log(log_level_info, verbose_, session_id_, what.str());
        }));

    if(socket_inside_->is_open())
    {
        socket_inside_->close();
    }
    if(socket_wallside_->is_open())
    {
        socket_wallside_->close();
    }
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

    boost::asio::dispatch(
                    ioc_
                    , boost::asio::bind_executor(strand_log_, [&](){
            std::ostringstream what;
            what << " deadline_inside_handshake_overtime ";
            write_log(log_level_info, verbose_, session_id_, what.str());
        }));

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

    boost::asio::dispatch(
                    ioc_
                    , boost::asio::bind_executor(strand_log_, [&](){
            std::ostringstream what;
            what << " deadline_inside_request_overtime ";
            write_log(log_level_info, verbose_, session_id_, what.str());
        }));

    write_response();
}

void session_local_proxy::deadline_inside_wallside_read_overtime(
        boost::system::error_code error
        )
{
    if(error)
    {
        return;
    }

    boost::asio::dispatch(
                    ioc_
                    , boost::asio::bind_executor(strand_log_, [&](){
            std::ostringstream what;
            what << " deadline_inside_wallside_read_overtime ";
            write_log(log_level_info, verbose_, session_id_, what.str());
        }));

    if(socket_inside_->is_open())
    {
        socket_inside_->close();
    }
    if(socket_wallside_->is_open())
    {
        socket_wallside_->close();
    }
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
        //write_log(1, 0, verbose_, session_id_, "[boost::asio::basic_stream_socket.async_receive] SOCKS5 handshake request is invalid. Closing session.");
        return 0;
    }

    if(buf->at(0) != 0x05)
    {
        return 0;
    }

    std::size_t size = buf->at(1);
    if(bytes_transferred < size + 2)
    {
        return 0;
    }

    return 1;
}

void session_local_proxy::handler_read_handshake_completed(
        std::shared_ptr<std::array<char, 1024>> buf
        , boost::system::error_code error
        , std::size_t bytes_transferred
        )
{
    if(error)
    {
        if(socket_inside_->is_open())
        {
            socket_inside_->close();
        }
        return;
    }

    boost::asio::dispatch(
                    ioc_
                    , boost::asio::bind_executor(strand_log_, [&](){
            std::ostringstream what;
            what << "read handshake";
            write_log(log_level_info, verbose_, session_id_, what.str());
        }));

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
                , boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::handler_write_handshake_completed, shared_from_this(), boost::placeholders::_1, boost::placeholders::_2)));
}

void session_local_proxy::handler_write_handshake_completed(
        boost::system::error_code error
        , std::size_t bytes_transferred
        )
{
    if(error)
    {
        //write_log(1, 0, verbose_, session_id_, "[boost::asio::basic_stream_socket.async_write] No appropriate auth method found. Closing session.");
        if(socket_inside_->is_open())
        {
            socket_inside_->close();
        }
        return;
    }

    boost::asio::dispatch(
                    ioc_
                    , boost::asio::bind_executor(strand_log_, [&](){
            std::ostringstream what;
            what << "write handshake";
            write_log(log_level_info, verbose_, session_id_, what.str());
        }));

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
                , boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::handler_write_refuse_handshake_completed, shared_from_this(), boost::placeholders::_1, boost::placeholders::_2)));
}

void session_local_proxy::handler_write_refuse_handshake_completed(
        boost::system::error_code error
        , std::size_t bytes_transferred
        )
{
    boost::asio::dispatch(
                    ioc_
                    , boost::asio::bind_executor(strand_log_, [&](){
            std::ostringstream what;
            what << "write refuse handshake";
            write_log(log_level_info, verbose_, session_id_, what.str());
        }));

    if(socket_inside_->is_open())
    {
        socket_inside_->close();
    }
}

void session_local_proxy::read_request()
{
    std::shared_ptr<std::vector<char>> buf(new std::vector<char>(1024, 0));
    boost::asio::async_read(
                    *socket_inside_
                    , boost::asio::buffer(*buf)
                    , boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::completion_condition_read_request, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2))
                    , boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::handler_read_request_completed, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2))
                );
}

std::size_t session_local_proxy::completion_condition_read_request(
        std::shared_ptr<std::vector<char>> buf
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
        //write_log(1, 0, verbose_, session_id_, "SOCKS5 request length is invalid. Closing session."); return;
        return 0;
    }

    if(buf->at(3) == 0x01)
    {
        if(bytes_transferred < (4 + 4 + 2))
        {
            return 0;
        }
    }
    else if(buf->at(3) == 0x03)
    {
        if(bytes_transferred < 5)
        {
            return 0;
        }

        if(bytes_transferred < (4 + 1 + buf->at(4) + 2))
        {
            return 0;
        }
    }
    else if(buf->at(3) == 0x04)
    {
        if(bytes_transferred < (4 + 16 + 2))
        {
            return 0;
        }
    }

    //值检查
    if(buf->at(0) != 0x05)
    {
        return 0;
    }

    if(buf->at(1) != 0x01)
    {
        return 0;
    }

    return 1;
}

void session_local_proxy::handler_read_request_completed(
        std::shared_ptr<std::vector<char>> buf
        , boost::system::error_code error
        , std::size_t bytes_transferred)
{
    if(error)
    {
        socket_inside_->close();
    }

    //收到了客户端的请求，设定时器要求必须返回请求响应
    deadline_inside_request_.expires_from_now(boost::posix_time::seconds(deadline_second_));
    deadline_inside_request_.async_wait(
                boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::deadline_inside_request_overtime, shared_from_this(), boost::placeholders::_1))
                );

    remote_host_atyp_ = buf->at(3);
    switch (buf->at(3))
    {
    case 0x01: // IP V4 addres

        std::copy(buf->begin() + 4, buf->begin() + 8, std::back_inserter(remote_host_bndaddr_));

        std::copy(buf->begin() + 8, buf->begin() + 10, std::back_inserter(remote_port_bndport_));

        //boost::asio::ip::address_v4(ntohl(*((uint32_t*)&buf->at(4)))).to_string();
        //std::to_string(ntohs(*((uint16_t*)&buf->at(8))));

        buf->resize(bytes_transferred);
        do_remote_proxy_connect(buf);

        break;
    case 0x03: // DOMAINNAME

        uint8_t host_length = buf->at(4);
        std::copy(buf->begin() + 4, buf->begin() + 4 + host_length, std::back_inserter(remote_host_bndaddr_));

        std::copy(buf->begin() + 8, buf->begin() + 10, std::back_inserter(remote_port_bndport_));

        //std::string(&buf->at(5), host_length);
        //std::to_string(ntohs(*((uint16_t*)&buf->at(5 + host_length))));

        buf->resize(bytes_transferred);
        do_remote_proxy_connect(buf);

        break;
    }

    //default:
        //write_log(1, 0, verbose_, session_id_, "unsupport_ed address type in SOCKS5 request. Closing session.");
        //break;
}

void session_local_proxy::do_remote_proxy_connect(
        std::shared_ptr<std::vector<char>> buf
        )
{
    boost::asio::ip::tcp::endpoint ep(boost::asio::ip::address::from_string(remote_proxy_host_), remote_proxy_port_);

    socket_wallside_->async_connect(
                ep
                , boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::handler_remote_proxy_connect_completed, shared_from_this(), buf, boost::placeholders::_1)));
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

    //std::ostringstream what; what << "connected to " << remote_proxy_ipv4_ << ":" << remote_proxy_port_;
    //            write_log(0, 1, verbose_, session_id_, what.str());
    write_remote_proxy_request(buf);
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
                , boost::asio::transfer_at_least(buf->size())
                , boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::handler_write_remote_proxy_request_completed, shared_from_this(), boost::placeholders::_1, boost::placeholders::_2))
                );
}

void session_local_proxy::handler_write_remote_proxy_request_completed(
        boost::system::error_code error
        , std::size_t bytes_transferred
        )
{
    if(error)
    {
        return;
    }

//            std::ostringstream what; what << "write_remote_proxy_request";
//            write_log(0, 1, verbose_, session_id_, what.str());

    read_remote_proxy_response();
}

void session_local_proxy::read_remote_proxy_response()
{
    std::shared_ptr<std::vector<char>> buf(new std::vector<char>(1024, 0));
    boost::asio::async_read(
                    *socket_wallside_
                    , boost::asio::buffer(*buf)
                    , boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::completion_condition_read_remote_proxy_response, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2))
                    , boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::handler_read_remote_proxy_response_completed, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2))
                );
}

std::size_t session_local_proxy::completion_condition_read_remote_proxy_response(
        std::shared_ptr<std::vector<char>> buf
        , boost::system::error_code const& error
        , std::size_t bytes_transferred
        )
{
    if(error)
    {
        return 0;
    }

    std::shared_ptr<std::vector<char>> buf_decode(new std::vector<char>(buf->size()));
    decode(buf->begin(), buf->end(), buf_decode->begin());

    if(bytes_transferred < 2)
    {
        //write_log(1, 0, verbose_, session_id_, "[boost::asio::basic_stream_socket.async_receive] SOCKS5 handshake request is invalid. Closing session.");
        return 0;
    }

    if(buf_decode->at(0) != 0x05)
    {
        return 0;
    }

    std::size_t size = buf_decode->at(1);
    if(bytes_transferred < size + 2)
    {
        return 0;
    }

    return 1;
}

void session_local_proxy::handler_read_remote_proxy_response_completed(
        std::shared_ptr<std::vector<char>> buf
        , boost::system::error_code const& error
        , std::size_t bytes_transferred
        )
{
    if(error)
    {
        return;
    }

    write_response_from_remote_proxy(buf);
}

void session_local_proxy::write_response_from_remote_proxy(
        std::shared_ptr<std::vector<char>> buf
        )
{
    boost::asio::async_write(
                *socket_inside_
                , boost::asio::buffer(*buf)
                , boost::asio::transfer_at_least(buf->size())
                , boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::handler_write_response_from_remote_proxy_completed, shared_from_this(), boost::placeholders::_1, boost::placeholders::_2))
                );
}

void session_local_proxy::handler_write_response_from_remote_proxy_completed(
        boost::system::error_code error
        , std::size_t bytes_transferred
        )
{
    if(error)
    {
        return;
    }

    boost::asio::dispatch(
                    ioc_
                    , boost::asio::bind_executor(strand_log_, [&](){
            std::ostringstream what;
            what << "write response (from remote proxy)";
            write_log(log_level_info, verbose_, session_id_, what.str());
        }));

    dealline_establish_.cancel();

    deadline_inside_request_.cancel();

    //            std::ostringstream what; what << "write_socks5_response_from_remote_proxy";
    //            write_log(0, 1, verbose_, session_id_, what.str());

    do_read_inside();
    do_read_wallside();
}

void session_local_proxy::write_response()
{
    std::shared_ptr<std::vector<char>> buf(new std::vector<char>);
    buf->push_back(0x05);
    buf->push_back(0x03);//不管具体什么原因无法返回响应，都按照 0x03网络不可达 处理
    buf->push_back(0x00);
    buf->push_back(remote_host_atyp_);
    if(remote_host_atyp_ == 0x03)
    {
        buf->push_back(remote_host_bndaddr_.size());
    }
    std::copy(remote_host_bndaddr_.begin(), remote_host_bndaddr_.end(), std::back_inserter(*buf));
    std::copy(remote_port_bndport_.begin(), remote_port_bndport_.end(), std::back_inserter(*buf));

    boost::asio::async_write(
                *socket_inside_
                , boost::asio::buffer(*buf)
                , boost::asio::transfer_at_least(buf->size())
                , boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::handler_write_response_completed, shared_from_this(), boost::placeholders::_1, boost::placeholders::_2))
                );
}

void session_local_proxy::handler_write_response_completed(
        boost::system::error_code error
        , std::size_t bytes_transferred
        )
{
    boost::asio::dispatch(
                    ioc_
                    , boost::asio::bind_executor(strand_log_, [&](){
            std::ostringstream what;
            what << "write refuse response (from local proxy)";
            write_log(log_level_info, verbose_, session_id_, what.str());
        }));

    if(socket_inside_->is_open())
    {
        socket_inside_->close();
    }
    if(socket_wallside_->is_open())
    {
        socket_wallside_->close();
    }
}

void session_local_proxy::do_read_inside()
{
    deadline_inside_read_.expires_from_now(boost::posix_time::seconds(deadline_read_second_));
    deadline_inside_read_.async_wait(
                boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::deadline_inside_wallside_read_overtime, shared_from_this(), boost::placeholders::_1))
                );

    std::shared_ptr<std::vector<char>> buf(new std::vector<char>(1024, 0));
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

    boost::asio::dispatch(
                ioc_
                , boost::asio::bind_executor(strand_log_, [&](){
        std::ostringstream what;
        what << " --> " << std::to_string(bytes_transferred) << " bytes";
        write_log(log_level_info, verbose_, session_id_, what.str());
    }));

    do_read_inside();

    auto buf_write = std::make_shared<std::vector<char>>(buf->begin(), buf->begin() + bytes_transferred);

    std::shared_ptr<std::vector<char>> buf_write_encode(new std::vector<char>(buf_write->size()));
    encode(buf_write->begin(), buf_write->end(), buf_write_encode->begin());

    do_write_wallside(buf_write_encode);
}

void session_local_proxy::do_write_wallside(
        std::shared_ptr<std::vector<char>> buf
        )
{
    socket_wallside_->async_write_some(
                boost::asio::buffer(*buf)
                , boost::asio::bind_executor(strand_wallside_write_, boost::bind(&session_local_proxy::handler_do_write_wallside_completed, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2))
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
        socket_wallside_->close();
    }

    if(bytes_transferred < buf->size())
    {
        auto buf_write = std::make_shared<std::vector<char>>(buf->begin() + bytes_transferred, buf->end());
        do_write_wallside(buf_write);
    }
}

void session_local_proxy::do_read_wallside()
{
    deadline_wallside_read_.expires_from_now(boost::posix_time::seconds(deadline_read_second_));
    deadline_wallside_read_.async_wait(
                boost::asio::bind_executor(strand_, boost::bind(&session_local_proxy::deadline_inside_wallside_read_overtime, shared_from_this(), boost::placeholders::_1))
                );

    std::shared_ptr<std::vector<char>> buf(new std::vector<char>(1024, 0));
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

    boost::asio::dispatch(
                ioc_
                , boost::asio::bind_executor(strand_log_, [&](){
        std::ostringstream what;
        what << " <-- " << std::to_string(bytes_transferred) << " bytes";
        write_log(log_level_info, verbose_, session_id_, what.str());
    }));

    do_read_wallside();

    auto buf_write = std::make_shared<std::vector<char>>(buf->begin(), buf->begin() + bytes_transferred);

    std::shared_ptr<std::vector<char>> buf_write_decode(new std::vector<char>(buf_write->size()));
    decode(buf_write->begin(), buf_write->end(), buf_write_decode->begin());

    do_write_inside(buf_write_decode);
}

void session_local_proxy::do_write_inside(
        std::shared_ptr<std::vector<char>> buf
        )
{
    socket_inside_->async_write_some(
                boost::asio::buffer(*buf)
                , boost::asio::bind_executor(strand_inside_write_, boost::bind(&session_local_proxy::handler_do_write_inside_completed, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2))
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
        return;
    }

    if(bytes_transferred < buf->size())
    {
        auto buf_write = std::make_shared<std::vector<char>>(buf->begin() + bytes_transferred, buf->end());
        do_write_inside(buf_write);
    }
}
