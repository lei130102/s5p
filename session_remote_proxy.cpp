#include "session_remote_proxy.h"

#include "log.h"
#include "encode.h"

#include <boost/asio.hpp>
#include <boost/bind.hpp>

std::shared_ptr<session_remote_proxy> session_remote_proxy::create(
        boost::asio::io_service& ioc
        , boost::asio::strand<boost::asio::io_service::executor_type>& strand_log
        , std::shared_ptr<boost::asio::ip::tcp::socket> socket_inside
        , unsigned session_id
        , short verbose
        )
{
    return std::shared_ptr<session_remote_proxy>(new session_remote_proxy(
                                        ioc
                                        , strand_log
                                        , socket_inside
                                        , session_id
                                        , verbose
                                        ));
}

session_remote_proxy::session_remote_proxy(
        boost::asio::io_service &ioc
        , boost::asio::strand<boost::asio::io_context::executor_type>& strand_log
        , std::shared_ptr<boost::asio::ip::tcp::socket> socket_inside
        , unsigned session_id
        , short verbose)
    :ioc_(ioc)
    , strand_log_(strand_log)
    , resolver_(ioc)
    , socket_inside_(socket_inside)
    , socket_wallside_(new boost::asio::ip::tcp::socket(ioc))
    , dealline_establish_(ioc)
    , deadline_inside_read_(ioc)
    , deadline_wallside_read_(ioc)
    , session_id_(session_id)
    , remote_host_atyp_('\0')
    , verbose_(verbose)
    , dealline_establish_second_(10)
    , deadline_read_second_(600)
    , strand_(boost::asio::make_strand(ioc))
    , strand_inside_read_(boost::asio::make_strand(ioc))
    , strand_inside_write_(boost::asio::make_strand(ioc))
    , strand_wallside_read_(boost::asio::make_strand(ioc))
    , strand_wallside_write_(boost::asio::make_strand(ioc))
{}

session_remote_proxy::~session_remote_proxy()
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
    deadline_inside_read_.cancel();
    deadline_wallside_read_.cancel();
}

void session_remote_proxy::deadline_wallside_overtime(
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
            what << " deadline_wallside_overtime ";
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

void session_remote_proxy::deadline_inside_wallside_read_overtime(
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

void session_remote_proxy::start()
{
    read_request_protocol();
}

void session_remote_proxy::read_request_protocol()
{
    dealline_establish_.expires_from_now(boost::posix_time::seconds(dealline_establish_second_));
    dealline_establish_.async_wait(
                boost::asio::bind_executor(strand_, boost::bind(&session_remote_proxy::deadline_wallside_overtime, shared_from_this(), boost::placeholders::_1))
                );

    std::shared_ptr<std::vector<char>> buf(new std::vector<char>(1024, 0));
    boost::asio::async_read(
                *socket_wallside_
                , boost::asio::buffer(*buf)
                , boost::asio::bind_executor(strand_, boost::bind(&session_remote_proxy::completion_condition_read_request_protocol, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2))
                , boost::asio::bind_executor(strand_, boost::bind(&session_remote_proxy::handler_read_request_protocol_completed, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2))
                );
}

std::size_t session_remote_proxy::completion_condition_read_request_protocol(
        std::shared_ptr<std::vector<char>> buf
        , boost::system::error_code error
        , std::size_t bytes_transferred
        )
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

    std::shared_ptr<std::vector<char>> buf_decode(new std::vector<char>(buf->size()));
    decode(buf->begin(), buf->end(), buf_decode->begin());

    //长度检查
    if(bytes_transferred < 4)
    {
        //write_log(1, 0, verbose_, session_id_, "SOCKS5 request length is invalid. Closing session."); return;
        return 0;
    }

    if(buf_decode->at(3) == 0x01)
    {
        if(bytes_transferred < (4 + 4 + 2))
        {
            return 0;
        }
    }
    else if(buf_decode->at(3) == 0x03)
    {
        if(bytes_transferred < 5)
        {
            return 0;
        }

        if(bytes_transferred < (4 + 1 + buf_decode->at(4) + 2))
        {
            return 0;
        }
    }
    else if(buf_decode->at(3) == 0x04)
    {
        if(bytes_transferred < (4 + 16 + 2))
        {
            return 0;
        }
    }

    //值检查
    if(buf_decode->at(0) != 0x05)
    {
        return 0;
    }

    if(buf_decode->at(1) != 0x01)
    {
        return 0;
    }

    return 1;
}

void session_remote_proxy::handler_read_request_protocol_completed(
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
            what << "read request protocol";
            write_log(log_level_info, verbose_, session_id_, what.str());
        }));

    std::shared_ptr<std::vector<char>> buf_decode(new std::vector<char>(buf->size()));
    decode(buf->begin(), buf->end(), buf_decode->begin());

    std::string remote_host;
    std::string remote_port;

    switch (buf_decode->at(3))
    {
    case 0x01: // IP V4 addres

        std::copy(buf_decode->begin() + 4, buf_decode->begin() + 8, std::back_inserter(remote_host_bndaddr_));

        std::copy(buf_decode->begin() + 8, buf_decode->begin() + 10, std::back_inserter(remote_port_bndport_));

        //boost::asio::ip::address_v4(ntohl(*((uint32_t*)&buf_decode->at(4)))).to_string();
        //std::to_string(ntohs(*((uint16_t*)&buf_decode->at(8))));

        buf_decode->resize(bytes_transferred);
        do_resolve(remote_host, remote_port);

        break;
    case 0x03: // DOMAINNAME

        uint8_t host_length = buf_decode->at(4);
        std::copy(buf_decode->begin() + 4, buf_decode->begin() + 4 + host_length, std::back_inserter(remote_host_bndaddr_));

        std::copy(buf_decode->begin() + 8, buf_decode->begin() + 10, std::back_inserter(remote_port_bndport_));

        //std::string(&buf_decode->at(5), host_length);
        //std::to_string(ntohs(*((uint16_t*)&buf_decode->at(5 + host_length))));

        buf_decode->resize(bytes_transferred);
        do_resolve(remote_host, remote_port);

        break;
    //default:
        //write_log(1, 0, verbose_, session_id_, "unsupport_ed address type in SOCKS5 request. Closing session.");
        //break;
    }
}

void session_remote_proxy::do_resolve(
        std::string const& remote_host
        , std::string const& remote_port)
{
    resolver_.async_resolve(
                boost::asio::ip::tcp::resolver::query(remote_host, remote_port)
                , boost::asio::bind_executor(strand_, boost::bind(&session_remote_proxy::handler_do_resolve_completed, shared_from_this(), boost::placeholders::_1, boost::placeholders::_2))
                );
}

void session_remote_proxy::handler_do_resolve_completed(
        boost::system::error_code error
        , boost::asio::ip::tcp::resolver::iterator iter
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
            what << "do resolve";
            write_log(log_level_info, verbose_, session_id_, what.str());
        }));

    do_connect(iter);
}

void session_remote_proxy::do_connect(
        boost::asio::ip::tcp::resolver::iterator& iter)
{
    socket_inside_->async_connect(
                *iter
                , boost::asio::bind_executor(strand_, boost::bind(&session_remote_proxy::handler_do_connect_completed, shared_from_this(), boost::placeholders::_1))
                );
}

void session_remote_proxy::handler_do_connect_completed(
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
            what << "do connect";
            write_log(log_level_info, verbose_, session_id_, what.str());
        }));

    write_response();
}

void session_remote_proxy::write_response()
{
    /*
    The SOCKS request information is sent by the client as soon as it has
    established a connection to the SOCKS server, and completed the
    authentication negotiations.  The server evaluates the request, and
    returns a reply formed as follows:
    +----+-----+-------+------+----------+----------+
    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    +----+-----+-------+------+----------+----------+
    | 1  |  1  | X'00' |  1   | Variable |    2     |
    +----+-----+-------+------+----------+----------+
    Where:
    o  VER    protocol version: X'05'
    o  REP    Reply field:
    o  X'00' succeeded
    o  X'01' general SOCKS server failure
    o  X'02' connection not allowed by ruleset
    o  X'03' Network unreachable
    o  X'04' Host unreachable
    o  X'05' Connection refused
    o  X'06' TTL expired
    o  X'07' Command not support_ed
    o  X'08' Address type not support_ed
    o  X'09' to X'FF' unassigned
    o  RSV    RESERVED
    o  ATYP   address type of following address
    o  IP V4 address: X'01'
    o  DOMAINNAME: X'03'
    o  IP V6 address: X'04'
    o  BND.ADDR       server bound address
    o  BND.PORT       server bound port_ in network octet order
    Fields marked RESERVED (RSV) must be set to X'00'.
    */

    std::shared_ptr<std::vector<char>> buf(new std::vector<char>);
    buf->push_back(0x05);
    buf->push_back(0x00);
    buf->push_back(0x00);
    buf->push_back(remote_host_atyp_);
    if(remote_host_atyp_ == 0x03)
    {
        buf->push_back(remote_host_bndaddr_.size());
    }
    std::copy(remote_host_bndaddr_.begin(), remote_host_bndaddr_.end(), std::back_inserter(*buf));
    std::copy(remote_port_bndport_.begin(), remote_port_bndport_.end(), std::back_inserter(*buf));

    std::shared_ptr<std::vector<char>> buf_encode(new std::vector<char>(buf->size()));
    encode(buf->begin(), buf->end(), buf_encode->begin());

    boost::asio::async_write(
                *socket_wallside_
                , boost::asio::buffer(*buf_encode)
                , boost::asio::transfer_at_least(buf_encode->size())
                , boost::asio::bind_executor(strand_, boost::bind(&session_remote_proxy::handler_write_response_completed, shared_from_this(), boost::placeholders::_1, boost::placeholders::_2))
                );
}

void session_remote_proxy::handler_write_response_completed(
        boost::system::error_code error
        , std::size_t bytes_transferred
        )
{
    if(error)
    {
        return;
    }

    dealline_establish_.cancel();

    boost::asio::dispatch(
                    ioc_
                    , boost::asio::bind_executor(strand_log_, [&](){
            std::ostringstream what;
            what << "write response";
            write_log(log_level_info, verbose_, session_id_, what.str());
        }));

    do_read_inside();
    do_read_wallside();
}

void session_remote_proxy::do_read_inside()
{
    deadline_inside_read_.expires_from_now(boost::posix_time::seconds(deadline_read_second_));
    deadline_inside_read_.async_wait(
                boost::asio::bind_executor(strand_, boost::bind(&session_remote_proxy::deadline_inside_wallside_read_overtime, shared_from_this(), boost::placeholders::_1))
                );

    std::shared_ptr<std::vector<char>> buf(new std::vector<char>(1024, 0));
    socket_inside_->async_read_some(
                boost::asio::buffer(*buf)
                , boost::asio::bind_executor(strand_inside_read_, boost::bind(&session_remote_proxy::handler_do_read_inside_completed, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2))
                );
}

void session_remote_proxy::handler_do_read_inside_completed(
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

void session_remote_proxy::do_write_wallside(
        std::shared_ptr<std::vector<char>> buf
        )
{
    socket_wallside_->async_write_some(
                boost::asio::buffer(*buf)
                , boost::asio::bind_executor(strand_wallside_write_, boost::bind(&session_remote_proxy::handler_do_write_wallside_completed, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2))
                );
}

void session_remote_proxy::handler_do_write_wallside_completed(
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

void session_remote_proxy::do_read_wallside()
{
    deadline_wallside_read_.expires_from_now(boost::posix_time::seconds(deadline_read_second_));
    deadline_wallside_read_.async_wait(
                boost::asio::bind_executor(strand_, boost::bind(&session_remote_proxy::deadline_inside_wallside_read_overtime, shared_from_this(), boost::placeholders::_1))
                );

    std::shared_ptr<std::vector<char>> buf(new std::vector<char>(1024, 0));
    socket_wallside_->async_read_some(
                boost::asio::buffer(*buf)
                , boost::asio::bind_executor(strand_wallside_read_, boost::bind(&session_remote_proxy::handler_do_read_wallside_completed, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2))
                );
}

void session_remote_proxy::handler_do_read_wallside_completed(
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

void session_remote_proxy::do_write_inside(
        std::shared_ptr<std::vector<char>> buf
        )
{
    socket_inside_->async_write_some(
                boost::asio::buffer(*buf)
                , boost::asio::bind_executor(strand_inside_write_, boost::bind(&session_remote_proxy::handler_do_write_inside_completed, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2))
                );
}

void session_remote_proxy::handler_do_write_inside_completed(
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
