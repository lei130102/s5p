#include "s5p.h"

#include <boost/date_time/posix_time/posix_time.hpp>

#include <cstdlib>
#include <string>
#include <memory>
#include <utility>
#include <fstream>
#include <map>
#include <string>
#include <sstream>
#include <thread>

std::shared_ptr<Session> Session::create(boost::asio::io_service& ioc, tcp::socket in_socket, unsigned session_id, size_t buffer_size, short verbose, std::string remote_proxy_ipv4, short remote_proxy_port)
{
    return std::shared_ptr<Session>(new Session(ioc, std::move(in_socket), session_id, buffer_size, verbose, remote_proxy_ipv4, remote_proxy_port));
}

Session::Session(boost::asio::io_service& ioc, tcp::socket in_socket, unsigned session_id, size_t buffer_size, short verbose, std::string remote_proxy_ipv4, short remote_proxy_port)
    :in_socket_(std::move(in_socket)),
        in_deadline_(ioc),
        out_socket_(ioc),
        out_deadline_(ioc),
        resolver(ioc),
        deadlineSecond_(20),
        buffer_size_(buffer_size),
        in_buf_(buffer_size),
        out_buf_(buffer_size),
        session_id_(session_id),
        verbose_(verbose),
        remote_proxy_ipv4_(remote_proxy_ipv4),
        remote_proxy_port_(remote_proxy_port)
{

}

Session::~Session()
{
    std::ostringstream what; what << "session " << session_id_ << " destroyed";
    write_log(0, 0, verbose_, session_id_, what.str());
}

void Session::start()
{
    in_deadline_.expires_at(boost::posix_time::ptime(boost::posix_time::max_date_time));
    out_deadline_.expires_at(boost::posix_time::ptime(boost::posix_time::max_date_time));

    read_handshake();

    check_in_deadline();
    check_out_deadline();
}

void Session::remote_proxy_start()
{
    in_deadline_.expires_at(boost::posix_time::ptime(boost::posix_time::max_date_time));
    out_deadline_.expires_at(boost::posix_time::ptime(boost::posix_time::max_date_time));

    read_request_protocol();

    check_in_deadline();
    check_out_deadline();
}

///////

void Session::check_in_deadline()
{
    auto self(shared_from_this());
    in_deadline_.async_wait(
                [this,self](const boost::system::error_code& error)
    {
        std::lock(in_socket_mutex_,in_deadline_mutex_,out_socket_mutex_,out_deadline_mutex_);
        std::lock_guard<std::mutex> lg1(in_socket_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg2(in_deadline_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg3(out_socket_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg4(out_deadline_mutex_,std::adopt_lock);
        if(!in_socket_.is_open())
        {
            return;
        }

        if(in_deadline_.expires_at() <= boost::posix_time::second_clock::universal_time())
        {
            std::ostringstream what; what << "in deadline";
            write_log(0, 1, verbose_, session_id_, what.str());

            in_socket_.close();
            in_deadline_.cancel();

            //注意，此时很可能out_deadline_处于不会超时情况，导致out_socket_.close();out_deadline_.cancel();不会被调用，进而Session对象无法析构
            //所以
            out_socket_.close();
            out_deadline_.cancel();
        }
        else
        {
            check_in_deadline();
        }
    });
}

void Session::check_out_deadline()
{
    auto self(shared_from_this());
    out_deadline_.async_wait(
                [this,self](const boost::system::error_code& error)
    {
        std::lock(in_socket_mutex_,in_deadline_mutex_,out_socket_mutex_,out_deadline_mutex_);
        std::lock_guard<std::mutex> lg1(in_socket_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg2(in_deadline_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg3(out_socket_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg4(out_deadline_mutex_,std::adopt_lock);
        if(!out_socket_.is_open())
        {
            return;
        }

        if(out_deadline_.expires_at() <= boost::posix_time::second_clock::universal_time())
        {
            std::ostringstream what; what << "out deadline";
            write_log(0, 1, verbose_, session_id_, what.str());

            out_socket_.close();
            out_deadline_.cancel();

            //注意，此时很可能in_deadline_处于不会超时情况，导致in_socket_.close();in_deadline_.cancel();不会被调用，进而Session对象无法析构
            //所以
            in_socket_.close();
            in_deadline_.cancel();
        }
        else
        {
            check_out_deadline();
        }
    });
}

void Session::read_handshake()
{
    auto self(shared_from_this());

    in_deadline_.expires_from_now(boost::posix_time::seconds(deadlineSecond_));
    in_socket_.async_receive(boost::asio::buffer(in_buf_),
        [this, self](boost::system::error_code ec, std::size_t length)
    {

        std::lock(in_socket_mutex_,in_deadline_mutex_,out_deadline_mutex_);
        std::lock_guard<std::mutex> lg1(in_socket_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg2(in_deadline_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg3(out_deadline_mutex_,std::adopt_lock);
        if(!in_socket_.is_open())
        {
            return;
        }

        if (!ec)
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
            if (length < 3 || in_buf_[0] != 0x05)
            {
                write_log(1, 0, verbose_, session_id_, "SOCKS5 handshake request is invalid. Closing session.");
                return;
            }

            uint8_t num_methods = in_buf_[1];
            // Prepare request
            in_buf_[1] = 0xFF;

            // Only 0x00 - 'NO AUTHENTICATION REQUIRED' is now support_ed
            for (uint8_t method = 0; method < num_methods; ++method)
                if (in_buf_[2 + method] == 0x00) { in_buf_[1] = 0x00; break; }

            write_handshake();
        }
        else
        {
            write_log(1, 0, verbose_, session_id_, "SOCKS5 handshake request", ec.message());

            in_socket_.close();
            in_deadline_.cancel();
            out_deadline_.cancel();
        }
    });
}

void Session::write_handshake()
{
    auto self(shared_from_this());

    in_deadline_.expires_from_now(boost::posix_time::seconds(deadlineSecond_));

    boost::asio::async_write(in_socket_, boost::asio::buffer(in_buf_, 2), // Always 2-byte according to RFC1928
        [this, self](boost::system::error_code ec, std::size_t length)
    {
        std::lock(in_socket_mutex_,in_deadline_mutex_,out_deadline_mutex_);
        std::lock_guard<std::mutex> lg1(in_socket_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg2(in_deadline_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg3(out_deadline_mutex_,std::adopt_lock);
        if(!in_socket_.is_open())
        {
            return;
        }

        if (!ec)
        {
            if (in_buf_[1] == 0xFF)
                return; // No appropriate auth method found. Close session.

            read_request();
        }
        else
        {
            write_log(1, 0, verbose_, session_id_, "SOCKS5 handshake response write", ec.message());
            in_socket_.close();
            in_deadline_.cancel();
            out_deadline_.cancel();
        }
    });
}

void Session::read_request()
{
    auto self(shared_from_this());

    in_deadline_.expires_from_now(boost::posix_time::seconds(deadlineSecond_));
    in_socket_.async_receive(boost::asio::buffer(in_buf_),
        [this, self](boost::system::error_code ec, std::size_t length)
    {
        std::lock(in_socket_mutex_,in_deadline_mutex_,out_deadline_mutex_);
        std::lock_guard<std::mutex> lg1(in_socket_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg2(in_deadline_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg3(out_deadline_mutex_,std::adopt_lock);
        if(!in_socket_.is_open())
        {
            return;
        }

        if (!ec)
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
            if (length < 5 || in_buf_[0] != 0x05 || in_buf_[1] != 0x01)
            {
                write_log(1, 0, verbose_, session_id_, "SOCKS5 request is invalid. Closing session.");
                return;
            }

            uint8_t addr_type = in_buf_[3], host_length;

            switch (addr_type)
            {
            case 0x01: // IP V4 addres
                if (length != 10)
                {
                    write_log(1, 0, verbose_, session_id_, "SOCKS5 request length is invalid. Closing session."); return;
                }
                remote_host_ = boost::asio::ip::address_v4(ntohl(*((uint32_t*)&in_buf_[4]))).to_string();
                remote_port_ = std::to_string(ntohs(*((uint16_t*)&in_buf_[8])));
                break;
            case 0x03: // DOMAINNAME
                host_length = in_buf_[4];
                if (length != (size_t)(5 + host_length + 2))
                {
                    write_log(1, 0, verbose_, session_id_, "SOCKS5 request length is invalid. Closing session."); return;
                }
                remote_host_ = std::string(&in_buf_[5], host_length);
                remote_port_ = std::to_string(ntohs(*((uint16_t*)&in_buf_[5 + host_length])));
                break;
            default:
                write_log(1, 0, verbose_, session_id_, "unsupport_ed address type in SOCKS5 request. Closing session.");
                break;
            }

            std::copy(in_buf_.begin(),in_buf_.begin()+length,std::back_inserter(request_buf_));
            in_deadline_.expires_at(boost::posix_time::ptime(boost::posix_time::max_date_time));
            do_remote_proxy_connect();
        }
        else
        {
            write_log(1, 0, verbose_, session_id_, "SOCKS5 request read", ec.message());
            in_socket_.close();
            in_deadline_.cancel();
            out_deadline_.cancel();
        }
    });
}

void Session::read_request_protocol()
{
    auto self(shared_from_this());

    in_deadline_.expires_from_now(boost::posix_time::seconds(deadlineSecond_));
    in_socket_.async_receive(boost::asio::buffer(in_buf_),
        [this, self](boost::system::error_code ec, std::size_t length)
    {
        std::lock(in_socket_mutex_,in_deadline_mutex_,out_deadline_mutex_);
        std::lock_guard<std::mutex> lg1(in_socket_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg2(in_deadline_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg3(out_deadline_mutex_,std::adopt_lock);
        if(!in_socket_.is_open())
        {
            return;
        }

        if (!ec)
        {
            std::vector<char> socks5Request = decodeSock5Request(std::vector<char>(in_buf_.begin(),in_buf_.begin()+length));

            if (socks5Request.size() < 5 || socks5Request[0] != 0x05 || socks5Request[1] != 0x01)
            {
                write_log(1, 0, verbose_, session_id_, "SOCKS5 request is invalid. Closing session.");
                return;
            }

            uint8_t addr_type = socks5Request[3], host_length;

            switch (addr_type)
            {
            case 0x01: // IP V4 addres
                if (socks5Request.size() != 10)
                {
                    write_log(1, 0, verbose_, session_id_, "SOCKS5 request length is invalid. Closing session."); return;
                }
                remote_host_ = boost::asio::ip::address_v4(ntohl(*((uint32_t*)&socks5Request[4]))).to_string();
                remote_port_ = std::to_string(ntohs(*((uint16_t*)&socks5Request[8])));
                break;
            case 0x03: // DOMAINNAME
                host_length = socks5Request[4];
                if (socks5Request.size() != (size_t)(5 + host_length + 2))
                {
                    write_log(1, 0, verbose_, session_id_, "SOCKS5 request length is invalid. Closing session."); return;
                }
                remote_host_ = std::string(&socks5Request[5], host_length);
                remote_port_ = std::to_string(ntohs(*((uint16_t*)&socks5Request[5 + host_length])));
                break;
            default:
                write_log(1, 0, verbose_, session_id_, "unsupport_ed address type in SOCKS5 request. Closing session.");
                break;
            }

            in_deadline_.expires_at(boost::posix_time::ptime(boost::posix_time::max_date_time));
            do_resolve();
        }
        else
        {
            write_log(1, 0, verbose_, session_id_, "SOCKS5 request read", ec.message());
            in_socket_.close();
            in_deadline_.cancel();
            out_deadline_.cancel();
        }

    });
}

///////////

void Session::do_resolve()
{
    auto self(shared_from_this());

    resolver.async_resolve(tcp::resolver::query( remote_host_, remote_port_ ),
        [this, self](const boost::system::error_code& ec, tcp::resolver::iterator it)
    {
        std::lock(in_socket_mutex_,resolver_mutex_,in_deadline_mutex_,out_deadline_mutex_);
        std::lock_guard<std::mutex> lg1(in_socket_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg2(resolver_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg3(in_deadline_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg4(out_deadline_mutex_,std::adopt_lock);
        if(!in_socket_.is_open())
        {
            return;
        }

        if (!ec)
        {
            do_connect(it);
        }
        else
        {
            std::ostringstream what; what << "failed to resolve " << remote_host_ << ":" << remote_port_;
            write_log(1, 0, verbose_, session_id_, what.str(), ec.message());
            in_socket_.close();
            resolver.cancel();
            in_deadline_.cancel();
            out_deadline_.cancel();
        }
    });
}

void Session::do_connect(tcp::resolver::iterator& it)
{
    auto self(shared_from_this());
    out_deadline_.expires_from_now(boost::posix_time::seconds(deadlineSecond_));
    out_socket_.async_connect(*it,
        [this, self](const boost::system::error_code& ec)
    {
        std::lock(in_socket_mutex_,out_socket_mutex_,resolver_mutex_,in_deadline_mutex_,out_deadline_mutex_);
        std::lock_guard<std::mutex> lg1(in_socket_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg2(out_socket_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg3(resolver_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg4(in_deadline_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg5(out_deadline_mutex_,std::adopt_lock);
        if(!in_socket_.is_open() || !out_socket_.is_open())
        {
            return;
        }

        if (!ec)
        {
            std::ostringstream what; what << "connected to " << remote_host_ << ":" << remote_port_;
            write_log(0, 1, verbose_, session_id_, what.str());
            out_deadline_.expires_at(boost::posix_time::ptime(boost::posix_time::max_date_time));
            write_response();
        }
        else
        {
            std::ostringstream what; what << "failed to connect " << remote_host_ << ":" << remote_port_;
            write_log(1, 0, verbose_, session_id_, what.str(), ec.message());
            in_socket_.close();
            out_socket_.close();
            resolver.cancel();
            in_deadline_.cancel();
            out_deadline_.cancel();
        }
    });
}

void Session::write_response()
{
    auto self(shared_from_this());

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
    in_buf_[0] = 0x05; in_buf_[1] = 0x00; in_buf_[2] = 0x00; in_buf_[3] = 0x01;
    uint32_t realRemoteIP = out_socket_.remote_endpoint().address().to_v4().to_ulong();
    uint16_t realRemoteport = htons(out_socket_.remote_endpoint().port());

    std::memcpy(&in_buf_[4], &realRemoteIP, 4);
    std::memcpy(&in_buf_[8], &realRemoteport, 2);

    auto responseEncode = std::make_shared<std::vector<char>>();
    *responseEncode = encodeSock5Response(std::vector<char>(in_buf_.begin(),in_buf_.begin()+10));

    in_deadline_.expires_from_now(boost::posix_time::seconds(deadlineSecond_));
    boost::asio::async_write(in_socket_, boost::asio::buffer(*responseEncode), // Always 10-byte according to RFC1928
        [this, self, responseEncode](boost::system::error_code ec, std::size_t length)
    {
        std::lock(in_socket_mutex_,out_socket_mutex_,resolver_mutex_,in_deadline_mutex_,out_deadline_mutex_);
        std::lock_guard<std::mutex> lg1(in_socket_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg2(out_socket_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg3(resolver_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg4(in_deadline_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg5(out_deadline_mutex_,std::adopt_lock);
        if(!in_socket_.is_open() || !out_socket_.is_open())
        {
            return;
        }

        if (!ec)
        {
            do_read(1, 3); // Read both sockets
        }
        else
        {
            write_log(1, 0, verbose_, session_id_, "SOCKS5 response write", ec.message());
            in_socket_.close();
            out_socket_.close();
            resolver.cancel();
            in_deadline_.cancel();
            out_deadline_.cancel();
        }
    });
}


/////////

void Session::do_remote_proxy_connect()
{
    boost::asio::ip::tcp::endpoint ep(boost::asio::ip::address::from_string(remote_proxy_ipv4_),remote_proxy_port_);

    auto self(shared_from_this());
    out_deadline_.expires_from_now(boost::posix_time::seconds(deadlineSecond_));
    out_socket_.async_connect(ep,
        [this, self](const boost::system::error_code& ec)
    {
        std::lock(in_socket_mutex_,in_deadline_mutex_,out_socket_mutex_,out_deadline_mutex_);
        std::lock_guard<std::mutex> lg1(in_socket_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg2(in_deadline_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg3(out_socket_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg4(out_deadline_mutex_,std::adopt_lock);
        if(!in_socket_.is_open() || !out_socket_.is_open())
        {
            return;
        }

        if (!ec)
        {
            std::ostringstream what; what << "connected to " << remote_proxy_ipv4_ << ":" << remote_proxy_port_;
            write_log(0, 1, verbose_, session_id_, what.str());
            write_remote_proxy_request();
        }
        else
        {
            std::ostringstream what; what << "failed to connect " << remote_proxy_ipv4_ << ":" << remote_proxy_port_;
            write_log(1, 0, verbose_, session_id_, what.str(), ec.message());

            in_socket_.close();
            out_socket_.close();
            in_deadline_.cancel();
            out_deadline_.cancel();
        }
    });
}

void Session::write_remote_proxy_request()
{
    auto self(shared_from_this());
    auto requestEncode = std::make_shared<std::vector<char>>();
    *requestEncode = encodeSock5Request(request_buf_);
    out_deadline_.expires_from_now(boost::posix_time::seconds(deadlineSecond_));
    boost::asio::async_write(out_socket_, boost::asio::buffer(*requestEncode),
        [this, self, requestEncode](boost::system::error_code ec, std::size_t length)
    {
        std::lock(in_socket_mutex_,in_deadline_mutex_,out_socket_mutex_,out_deadline_mutex_);
        std::lock_guard<std::mutex> lg1(in_socket_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg2(in_deadline_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg3(out_socket_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg4(out_deadline_mutex_,std::adopt_lock);
        if(!in_socket_.is_open() || !out_socket_.is_open())
        {
            return;
        }

        if(!ec)
        {
            std::ostringstream what; what << "write_remote_proxy_request";
            write_log(0, 1, verbose_, session_id_, what.str());

            read_remote_proxy_response();
        }
        else
        {
            write_log(1, 0, verbose_, session_id_, "SOCKS5 handshake response write", ec.message());
            in_socket_.close();
            out_socket_.close();
            in_deadline_.cancel();
            out_deadline_.cancel();
        }
    });
}

void Session::read_remote_proxy_response()
{
    auto self(shared_from_this());
    out_deadline_.expires_from_now(boost::posix_time::seconds(deadlineSecond_));
    out_socket_.async_receive(boost::asio::buffer(out_buf_),
        [this, self](boost::system::error_code ec, std::size_t length)
    {
        std::lock(in_socket_mutex_,in_deadline_mutex_,out_socket_mutex_,out_deadline_mutex_);
        std::lock_guard<std::mutex> lg1(in_socket_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg2(in_deadline_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg3(out_socket_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg4(out_deadline_mutex_,std::adopt_lock);
        if(!in_socket_.is_open() || !out_socket_.is_open())
        {
            return;
        }

        if(!ec)
        {
            std::vector<char> socks5Response = decodeSock5Response(std::vector<char>(out_buf_.begin(),out_buf_.begin()+length));

            std::ostringstream what; what << "read_remote_proxy_response";
            write_log(0, 1, verbose_, session_id_, what.str());

            if(socks5Response.size() < 10 || socks5Response[0] != 0x05)
            {
                write_log(1, 0, verbose_, session_id_, "SOCKS5 handshake request is invalid. Closing session.");
                return;
            }

            if(socks5Response[1] != 0x00)
            {
                write_log(1, 0, verbose_, session_id_, "SOCKS5 request not succeeded. Closing session.");
                return;
            }

            in_buf_.clear();
            std::copy(socks5Response.begin(),socks5Response.end(),std::back_inserter(in_buf_));
            out_deadline_.expires_at(boost::posix_time::ptime(boost::posix_time::max_date_time));
            write_response_from_remote_proxy();
        }
        else
        {
            write_log(1, 0, verbose_, session_id_, "SOCKS5 handshake response write", ec.message());
            in_socket_.close();
            out_socket_.close();
            in_deadline_.cancel();
            out_deadline_.cancel();
        }
    });
}

void Session::write_response_from_remote_proxy()
{
    auto self(shared_from_this());

    in_deadline_.expires_from_now(boost::posix_time::seconds(deadlineSecond_));
    boost::asio::async_write(in_socket_, boost::asio::buffer(in_buf_), // Always 10-byte according to RFC1928
        [this, self](boost::system::error_code ec, std::size_t length)
    {
        std::lock(in_socket_mutex_,in_deadline_mutex_,out_socket_mutex_,out_deadline_mutex_);
        std::lock_guard<std::mutex> lg1(in_socket_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg2(in_deadline_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg3(out_socket_mutex_,std::adopt_lock);
        std::lock_guard<std::mutex> lg4(out_deadline_mutex_,std::adopt_lock);
        if(!in_socket_.is_open() || !out_socket_.is_open())
        {
            return;
        }

        if (!ec)
        {
            std::ostringstream what; what << "write_socks5_response_from_remote_proxy";
            write_log(0, 1, verbose_, session_id_, what.str());

            do_read(2, 3); // Read both sockets
        }
        else
        {
            write_log(1, 0, verbose_, session_id_, "SOCKS5 response write", ec.message());
            in_socket_.close();
            out_socket_.close();
            in_deadline_.cancel();
            out_deadline_.cancel();
        }
    });
}

void Session::do_read(int protocol, int direction)
{
    auto self(shared_from_this());

    // We must divide reads by direction to not permit second read call on the same socket.
    if (direction & 0x1)
    {
        auto read_buf = std::make_shared<std::vector<char>>(buffer_size_);
        in_deadline_.expires_from_now(boost::posix_time::seconds(deadlineSecond_));
        in_socket_.async_receive(boost::asio::buffer(*read_buf),
            [this, self, read_buf, protocol](boost::system::error_code ec, std::size_t length)
        {
            std::lock(in_socket_mutex_,out_socket_mutex_,resolver_mutex_,in_deadline_mutex_,out_deadline_mutex_);
            std::lock_guard<std::mutex> lg1(in_socket_mutex_,std::adopt_lock);
            std::lock_guard<std::mutex> lg2(out_socket_mutex_,std::adopt_lock);
            std::lock_guard<std::mutex> lg3(resolver_mutex_,std::adopt_lock);
            std::lock_guard<std::mutex> lg4(in_deadline_mutex_,std::adopt_lock);
            std::lock_guard<std::mutex> lg5(out_deadline_mutex_,std::adopt_lock);
            if(!in_socket_.is_open() || !out_socket_.is_open())
            {
                return;
            }

            if (!ec)
            {
                std::ostringstream what; what << "--> " << std::to_string(length) << " bytes";
                write_log(0, 2, verbose_, session_id_, what.str());

                auto write_buf = std::make_shared<std::vector<char>>(read_buf->begin(),read_buf->begin()+length);
                if(protocol == 1)
                {
                    //对in_buf_进行解密
                    *write_buf = decodeInfo(*write_buf);
                    length = write_buf->size();
                }

                do_write(protocol, 1, write_buf);
            }
            else //if (ec != boost::asio::error::eof)
            {
                write_log(2, 1, verbose_, session_id_, "closing session. Client socket read error", ec.message());
                // Most probably client closed socket. Let's close both sockets and exit session.
                in_socket_.close();
                out_socket_.close();
                resolver.cancel();
                in_deadline_.cancel();
                out_deadline_.cancel();
            }

        });
    }



    if (direction & 0x2)
    {
        auto read_buf = std::make_shared<std::vector<char>>(buffer_size_);
        out_deadline_.expires_from_now(boost::posix_time::seconds(deadlineSecond_));
        out_socket_.async_receive(boost::asio::buffer(*read_buf),
            [this, self, read_buf, protocol](boost::system::error_code ec, std::size_t length)
        {
            std::lock(in_socket_mutex_,out_socket_mutex_,resolver_mutex_,in_deadline_mutex_,out_deadline_mutex_);
            std::lock_guard<std::mutex> lg1(in_socket_mutex_,std::adopt_lock);
            std::lock_guard<std::mutex> lg2(out_socket_mutex_,std::adopt_lock);
            std::lock_guard<std::mutex> lg3(resolver_mutex_,std::adopt_lock);
            std::lock_guard<std::mutex> lg4(in_deadline_mutex_,std::adopt_lock);
            std::lock_guard<std::mutex> lg5(out_deadline_mutex_,std::adopt_lock);
            if(!in_socket_.is_open() || !out_socket_.is_open())
            {
                return;
            }

            if (!ec)
            {
                std::ostringstream what; what << "<-- " << std::to_string(length) << " bytes";
                write_log(0, 2, verbose_, session_id_, what.str());

                auto write_buf = std::make_shared<std::vector<char>>(read_buf->begin(),read_buf->begin()+length);
                if(protocol == 2)
                {
                    //对out_buf_进行解密
                    *write_buf = decodeInfo(*write_buf);
                    length = write_buf->size();
                }

                do_write(protocol, 2, write_buf);
            }
            else //if (ec != boost::asio::error::eof)
            {
                write_log(2, 1, verbose_, session_id_, "closing session. Remote socket read error", ec.message());
                // Most probably remote server closed socket. Let's close both sockets and exit session.
                in_socket_.close();
                out_socket_.close();
                resolver.cancel();
                in_deadline_.cancel();
                out_deadline_.cancel();
            }
        });
    }

}

void Session::do_write(int protocol, int direction, std::shared_ptr<std::vector<char>> write_buf)
{
    auto self(shared_from_this());

    switch (direction)
    {
    case 1:

        if(protocol==1)
        {
            //对in_buf_进行加密
            *write_buf = encodeInfo(*write_buf);
        }

        out_deadline_.expires_from_now(boost::posix_time::seconds(deadlineSecond_));
        boost::asio::async_write(out_socket_, boost::asio::buffer(*write_buf),
            [this, self, write_buf, protocol](boost::system::error_code ec, std::size_t length)
            {
            std::lock(in_socket_mutex_,out_socket_mutex_,resolver_mutex_,in_deadline_mutex_,out_deadline_mutex_);
            std::lock_guard<std::mutex> lg1(in_socket_mutex_,std::adopt_lock);
            std::lock_guard<std::mutex> lg2(out_socket_mutex_,std::adopt_lock);
            std::lock_guard<std::mutex> lg3(resolver_mutex_,std::adopt_lock);
            std::lock_guard<std::mutex> lg4(in_deadline_mutex_,std::adopt_lock);
            std::lock_guard<std::mutex> lg5(out_deadline_mutex_,std::adopt_lock);
            if(!in_socket_.is_open() || !out_socket_.is_open())
            {
                return;
            }

                if (!ec)
                {
                    do_read(protocol, 1);
                }
                else
                {
                    write_log(2, 1, verbose_, session_id_, "closing session. Client socket write error", ec.message());
                    // Most probably client closed socket. Let's close both sockets and exit session.
                    in_socket_.close();
                    out_socket_.close();
                    resolver.cancel();
                    in_deadline_.cancel();
                    out_deadline_.cancel();
                }
            });
        break;
    case 2:

        if(protocol==2)
        {
            //对out_buf_进行加密
            *write_buf = encodeInfo(*write_buf);
        }

        in_deadline_.expires_from_now(boost::posix_time::seconds(deadlineSecond_));
        boost::asio::async_write(in_socket_, boost::asio::buffer(*write_buf),
            [this, self, write_buf, protocol](boost::system::error_code ec, std::size_t length)
            {
            std::lock(in_socket_mutex_,out_socket_mutex_,resolver_mutex_,in_deadline_mutex_,out_deadline_mutex_);
            std::lock_guard<std::mutex> lg1(in_socket_mutex_,std::adopt_lock);
            std::lock_guard<std::mutex> lg2(out_socket_mutex_,std::adopt_lock);
            std::lock_guard<std::mutex> lg3(resolver_mutex_,std::adopt_lock);
            std::lock_guard<std::mutex> lg4(in_deadline_mutex_,std::adopt_lock);
            std::lock_guard<std::mutex> lg5(out_deadline_mutex_,std::adopt_lock);
            if(!in_socket_.is_open() || !out_socket_.is_open())
            {
                return;
            }

                if (!ec)
                {
                    do_read(protocol, 2);
                }
                else
                {
                    write_log(2, 1, verbose_, session_id_, "closing session. Remote socket write error", ec.message());
                    // Most probably remote server closed socket. Let's close both sockets and exit session.
                    in_socket_.close();
                    out_socket_.close();
                    resolver.cancel();
                    in_deadline_.cancel();
                    out_deadline_.cancel();
                }
            });
        break;
    }
}

std::vector<char> Session::encodeSock5Request(const std::vector<char>& request)
{
    return encode(request);
}

std::vector<char> Session::decodeSock5Request(const std::vector<char>& request)
{
    return decode(request);
}

std::vector<char> Session::encodeSock5Response(const std::vector<char>& response)
{
    return encode(response);
}

std::vector<char> Session::decodeSock5Response(const std::vector<char>& response)
{
    return decode(response);
}

std::vector<char> Session::encodeInfo(std::vector<char> info)
{
    return encode(info);
}

std::vector<char> Session::decodeInfo(std::vector<char> info)
{
    return decode(info);
}

std::vector<char> Session::encode(std::vector<char> v)
{
    std::vector<char> result;

    for(const auto& item : v)
    {
        result.push_back(item^108);
    }

    return result;
}

std::vector<char> Session::decode(std::vector<char> v)
{
    std::vector<char> result;

    for(const auto& item : v)
    {
        result.push_back(item^108);
    }

    return result;
}

///////////////////////////////////////

Server::Server(boost::asio::io_service& ioc, short port, unsigned buffer_size, short verbose, std::string remote_ipv4, short remote_port)
    : ioc_(ioc), acceptor_(ioc),
    in_socket_(ioc), buffer_size_(buffer_size), verbose_(verbose), session_id_(0),remote_ipv4_(remote_ipv4),remote_port_(remote_port)
{
    acceptor_.open(tcp::v4());
    acceptor_.set_option(boost::asio::socket_base::reuse_address(true));
    acceptor_.bind(tcp::endpoint(tcp::v4(), port));
    //acceptor_.listen(boost::asio::socket_base::max_listen_connections);
    acceptor_.listen(0x7fffffff);

    for(int i=0;i<10;++i)
    {
        do_accept();
    }
}

void Server::do_accept()
{
    acceptor_.async_accept(in_socket_,
        [this](boost::system::error_code ec)
        {
            if (!ec)
            {
                if(remote_ipv4_ == "0.0.0.0")
                {//remote_proxy
                    Session::create(ioc_, std::move(in_socket_), session_id_++, buffer_size_, verbose_, remote_ipv4_, remote_port_)->remote_proxy_start();
                }
                else
                {//local_proxy
                    Session::create(ioc_, std::move(in_socket_), session_id_++, buffer_size_, verbose_, remote_ipv4_, remote_port_)->start();
                }
            }
            else
                write_log(1, 0, verbose_, session_id_, "socket accept error", ec.message());

            do_accept();
        });
}
