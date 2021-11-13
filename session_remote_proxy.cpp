#include "session_remote_proxy.h"

#include "log.h"
#include "encode.h"

#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include <iterator>

std::shared_ptr<session_remote_proxy> session_remote_proxy::create(
        boost::asio::io_service& ioc_log
        , boost::asio::strand<boost::asio::io_service::executor_type>& strand_log
        , boost::asio::io_service& ioc
        , std::shared_ptr<boost::asio::ip::tcp::socket> socket
        , short remote_proxy_port
        , unsigned session_id
        , short verbose
        )
{
    return std::shared_ptr<session_remote_proxy>(new session_remote_proxy(
                                        ioc_log
                                        , strand_log
                                        , ioc
                                        , socket
                                        , remote_proxy_port
                                        , session_id
                                        , verbose
                                        ));
}

session_remote_proxy::session_remote_proxy(
        boost::asio::io_service &ioc_log
        , boost::asio::strand<boost::asio::io_context::executor_type>& strand_log
        , boost::asio::io_service &ioc
        , std::shared_ptr<boost::asio::ip::tcp::socket> socket
        , short remote_proxy_port
        , unsigned session_id
        , short verbose)
    :ioc_log_(ioc_log)
    , strand_log_(strand_log)
    , ioc_(ioc)
    , resolver_(ioc)
    , socket_inside_(new boost::asio::ip::tcp::socket(ioc))
    , socket_wallside_(socket)
    , dealline_establish_(ioc)
    , deadline_inside_wallside_(ioc)
    , remote_proxy_port_(remote_proxy_port)
	, remote_host_atyp_('\0')
    , session_id_(session_id)
    , verbose_(verbose)
    , dealline_establish_second_(12)
    , deadline_inside_wallside_second_(20)
    , strand_(boost::asio::make_strand(ioc))
{
    write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, "created");
}

session_remote_proxy::~session_remote_proxy()
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
    deadline_inside_wallside_.cancel();

    write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, "destroyed");
}

void session_remote_proxy::deadline_wallside_overtime(
        boost::system::error_code error
        )
{
    if(error)
    {
        return;
    }

    write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, "deadline_wallside_overtime");

    boost::system::error_code ec;
    socket_inside_->shutdown(boost::asio::socket_base::shutdown_both, ec);
    socket_wallside_->shutdown(boost::asio::socket_base::shutdown_both, ec);
}

void session_remote_proxy::deadline_inside_wallside_overtime(
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

    if(buf_decode->at(1) != 0x01)
    {
        return 1;
    }

    return 0;
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

    std::shared_ptr<std::vector<char>> buf_decode(new std::vector<char>(bytes_transferred));
    decode(buf->begin(), buf->begin() + bytes_transferred, buf_decode->begin());

    remote_host_atyp_ = buf_decode->at(3);

    std::string remote_host;
    std::string remote_port;

    switch (buf_decode->at(3))
    {
    case 0x01: // IP V4 addres
        {
            std::copy(buf_decode->begin() + 4, buf_decode->begin() + 4 + 4, std::back_inserter(remote_host_bndaddr_));
            std::copy(buf_decode->begin() + 4 + 4, buf_decode->begin() + 4 + 4 + 2, std::back_inserter(remote_port_bndport_));

            remote_host = boost::asio::ip::address_v4(ntohl(*((uint32_t*)&buf_decode->at(4)))).to_string();
            remote_port = std::to_string(ntohs(*((uint16_t*)&buf_decode->at(4 + 4))));

            do_resolve(remote_host, remote_port);
        }
        break;
    case 0x03: // DOMAINNAME
        {
            uint8_t host_length = buf_decode->at(4);

            std::copy(buf_decode->begin() + 4, buf_decode->begin() + 4 + 1 + host_length, std::back_inserter(remote_host_bndaddr_));
            std::copy(buf_decode->begin() + 4 + 1 + host_length, buf_decode->begin() + 4 + 1 + host_length + 2, std::back_inserter(remote_port_bndport_));

            remote_host = std::string(&buf_decode->at(4 + 1), host_length);

	    	//{
	    	//	std::ostringstream what;
	    	//	what << "0x03 remote_host:" << remote_host;
	    	//	write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, what.str());
	    	//}

            remote_port = std::to_string(ntohs(*((uint16_t*)&buf_decode->at(4 + 1 + host_length))));

	    	//{
	    	//	std::ostringstream what;
	    	//	what << "0x03 remote_port:" << remote_port;
	    	//	write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, what.str());
	    	//}

            do_resolve(remote_host, remote_port);
        }
        break;
    case 0x04: // IP V6 addres
        {
		    std::copy(buf_decode->begin() + 4, buf_decode->begin() + 4 + 16, std::back_inserter(remote_host_bndaddr_));
			std::copy(buf_decode->begin() + 4 + 16, buf_decode->begin() + 4 + 16 + 2, std::back_inserter(remote_port_bndport_));

            auto ipv6 = boost::asio::ip::make_address_v6(&buf_decode->at(4)).to_bytes();
            std::reverse(ipv6.begin(), ipv6.end());

            remote_host = std::string(ipv6.begin(), ipv6.end());
            remote_port = std::to_string(ntohs(*((uint16_t*)&buf_decode->at(4 + 16))));

            do_resolve(remote_host, remote_port);
        }
        break;
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
        , boost::asio::ip::tcp::resolver::results_type results
        )
{
    if(error)
    {
		std::ostringstream what;
		what << "handler_do_resolve_completed error:" << error.value() << " " << error.message();
		write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, what.str());

        return;
    }

	write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, "do resolve");

    do_connect(results);
}

void session_remote_proxy::do_connect(
        boost::asio::ip::tcp::resolver::results_type results
        )
{
    for (auto result : results)
    {
        if (result.endpoint().address().is_v6())
        {
            continue;
        }

        write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, 
            result.endpoint().address().to_string() + std::string(" ") + std::to_string(result.endpoint().port()));

        std::shared_ptr<boost::asio::ip::tcp::socket> socket_inside_candidate(new boost::asio::ip::tcp::socket(ioc_));

        socket_inside_candidate->async_connect(
            result.endpoint()
            , boost::asio::bind_executor(strand_, boost::bind(&session_remote_proxy::handler_do_connect_completed, shared_from_this(), socket_inside_candidate, boost::placeholders::_1))
        );

        break;
    }
}

void session_remote_proxy::handler_do_connect_completed(
        std::shared_ptr<boost::asio::ip::tcp::socket> socket
        , boost::system::error_code error
        )
{
    if(error)
    {
		std::ostringstream what;
		what << "handler_do_connect_completed error:" << error.value() << " " << error.message();
		write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, what.str());

        return;
    }

	write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, "do connect");

    if (!(socket_inside_->is_open()))
    {
        socket_inside_ = socket;

        write_response();
    }
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

//    {
//        //返回远程代理的ip和端口
//        boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), remote_proxy_port_);

//        buf->push_back(0x05);
//        buf->push_back(0x00);
//        buf->push_back(0x00);
//        buf->push_back(0x01);//远程代理的ip是ipv4
//        auto ip = ep.address().to_v4().to_bytes();
//        buf->insert(buf->end(), ip.begin(), ip.end());
//        auto port = ep.port();
//        buf->push_back(*((char*)(&port)));
//        buf->push_back(*((char*)(&port) + 1));
//    }

    {
        //返回原来的ip和端口
        buf->push_back(0x05);
        buf->push_back(0x00);
        buf->push_back(0x00);
        buf->push_back(remote_host_atyp_);

        buf->insert(buf->end(), remote_host_bndaddr_.begin(), remote_host_bndaddr_.end());
        buf->insert(buf->end(), remote_port_bndport_.begin(), remote_port_bndport_.end());
    }

    std::shared_ptr<std::vector<char>> buf_encode(new std::vector<char>(buf->size()));
    encode(buf->begin(), buf->end(), buf_encode->begin());

    boost::asio::async_write(
                *socket_wallside_
                , boost::asio::buffer(*buf_encode)
                , boost::asio::transfer_at_least(buf_encode->size())
                , boost::asio::bind_executor(strand_, boost::bind(&session_remote_proxy::handler_write_response_completed, shared_from_this(), buf_encode//注意必须要传递他，以延长buf_encode的生命周期，使boost::asio::buffer(*buf_encode)一直有效
                    , boost::placeholders::_1, boost::placeholders::_2))
                );
}

void session_remote_proxy::handler_write_response_completed(
        std::shared_ptr<std::vector<char>> buf
        , boost::system::error_code error
        , std::size_t bytes_transferred
        )
{
    if(error)
    {
        return;
    }

    dealline_establish_.cancel();

    do_read_wallside();
    do_read_inside();
}

///////////////////////////////////////////////////////////////////////////

void session_remote_proxy::do_read_wallside()
{
    {
        std::lock_guard<std::recursive_mutex> lg(inside_wallside_mutex);

        deadline_inside_wallside_.expires_from_now(boost::posix_time::seconds(deadline_inside_wallside_second_));
        deadline_inside_wallside_.async_wait(
                    boost::bind(&session_remote_proxy::deadline_inside_wallside_overtime, shared_from_this(), boost::placeholders::_1)
                    );
    }

    std::shared_ptr<std::vector<char>> buf(new std::vector<char>(40960, 0));
    socket_wallside_->async_read_some(
                boost::asio::buffer(*buf)
                , boost::bind(&session_remote_proxy::handler_do_read_wallside_completed, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2)
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

    std::ostringstream what;
    what << " <-- " << std::to_string(bytes_transferred) << " bytes";
    write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, what.str());

    std::shared_ptr<std::vector<char>> buf_write(new std::vector<char>(buf->begin(), buf->begin() + bytes_transferred));
    std::shared_ptr<std::vector<char>> buf_write_decode(new std::vector<char>(buf_write->size(), 0));
    decode(buf_write->begin(), buf_write->end(), buf_write_decode->begin());

    do_write_inside(buf_write_decode);
}

void session_remote_proxy::do_write_inside(
        std::shared_ptr<std::vector<char>> buf
        )
{
    {
        std::lock_guard<std::recursive_mutex> lg(inside_wallside_mutex);

        deadline_inside_wallside_.expires_from_now(boost::posix_time::seconds(deadline_inside_wallside_second_));
        deadline_inside_wallside_.async_wait(
                    boost::bind(&session_remote_proxy::deadline_inside_wallside_overtime, shared_from_this(), boost::placeholders::_1)
                    );
    }

    boost::asio::async_write(
                *socket_inside_
                , boost::asio::buffer(*buf)
                , boost::asio::transfer_at_least(buf->size())
                , boost::bind(&session_remote_proxy::handler_do_write_inside_completed, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2)
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

    do_read_wallside();
}

void session_remote_proxy::do_read_inside()
{
    {
        std::lock_guard<std::recursive_mutex> lg(inside_wallside_mutex);

        deadline_inside_wallside_.expires_from_now(boost::posix_time::seconds(deadline_inside_wallside_second_));
        deadline_inside_wallside_.async_wait(
                    boost::bind(&session_remote_proxy::deadline_inside_wallside_overtime, shared_from_this(), boost::placeholders::_1)
                    );
    }

    std::shared_ptr<std::vector<char>> buf(new std::vector<char>(40960, 0));
    socket_inside_->async_read_some(
                boost::asio::buffer(*buf)
                , boost::bind(&session_remote_proxy::handler_do_read_inside_completed, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2)
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

	std::ostringstream what;
	what << " --> " << std::to_string(bytes_transferred) << " bytes";
    write_log(ioc_log_, strand_log_, log_level_info, verbose_, session_id_, what.str());

    std::shared_ptr<std::vector<char>> buf_write(new std::vector<char>(buf->begin(), buf->begin() + bytes_transferred));
    std::shared_ptr<std::vector<char>> buf_write_encode(new std::vector<char>(buf_write->size(), 0));
    encode(buf_write->begin(), buf_write->end(), buf_write_encode->begin());

    do_write_wallside(buf_write_encode);
}

void session_remote_proxy::do_write_wallside(
        std::shared_ptr<std::vector<char>> buf
        )
{
    {
        std::lock_guard<std::recursive_mutex> lg(inside_wallside_mutex);

        deadline_inside_wallside_.expires_from_now(boost::posix_time::seconds(deadline_inside_wallside_second_));
        deadline_inside_wallside_.async_wait(
                    boost::bind(&session_remote_proxy::deadline_inside_wallside_overtime, shared_from_this(), boost::placeholders::_1)
                    );
    }

    boost::asio::async_write(
                *socket_wallside_
                , boost::asio::buffer(*buf)
                , boost::asio::transfer_at_least(buf->size())
                , boost::bind(&session_remote_proxy::handler_do_write_wallside_completed, shared_from_this(), buf, boost::placeholders::_1, boost::placeholders::_2)
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

    do_read_inside();
}

