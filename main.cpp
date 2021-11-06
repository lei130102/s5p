#include "server.h"
#include "log.h"

#include <thread>

#include <boost/locale.hpp>
#include <boost/program_options.hpp>
#include <boost/asio.hpp>

int main(int argc, char* argv[])
{

    //sock5代理服务器端

    //Linux
    //To build on Linux install Boost library and run the following command:
    //g++ -Wall -std=c++11 boost_socks5.cpp -o boost_socks5 -lboost_system -lboost_thread -lpthread

    //Windows
    //To build on Windows (mingw-w64)
    //Run the following command:
    //g++ -Wall -std=c++11 -I <Path_to_Boost_Include> boost_socks5.cpp -o boost_socks5 -static -L <Path_to_Boost_Libs> -lboost_system -lboost_thread -lwsock32 -lws2_32
    //Ignore Boost std::auto_ptr warnings if any.
    //To build on Windows (MS Visual Studio)
    //Run ‘Developer Command Prompt for VS2015’ and use the following command:
    //cl /EHsc /MD /I <Path_to_Boost_Include> /Feboost_socks5.exe boost_socks5.cpp /link /LIBPATH:<Path_to_Boost_Libs>

    try
    {
        boost::program_options::options_description desc("All options");
        desc.add_options()
                ("port,p",boost::program_options::value<short>()->default_value(1080),"local port to listen")
                ("verbose,v",boost::program_options::value<short>()->default_value(2),"verbosity level (0 - errors only, 1 - connect/disconnect, 2 - traffic packets size)")
                ("remoteipv4",boost::program_options::value<std::string>()->default_value(std::string("0.0.0.0")),"remote proxy IPv4")
                ("remoteport",boost::program_options::value<short>()->default_value(8803),"remote proxy port")
                ("help","help message");
        boost::program_options::variables_map vm;
        boost::program_options::store(boost::program_options::parse_command_line(argc,argv,desc),vm);
        boost::program_options::notify(vm);
        try {
            boost::program_options::store(boost::program_options::parse_config_file<char>("s5p.conf",desc),vm);
        } catch (const boost::program_options::reading_file& e) {
            std::cout << "failed to open file 's5p.conf': " << e.what() << "\n";
        }
        boost::program_options::notify(vm);

        //程序需要两个/组套接字，所以对应两个/组io_service对象(根据创建关系)

        //io_service对象是线程安全的可以多个线程同时 io_service::run() ，不过如果一个 io_service 对象仅在一个线程中 io_service::run() ，那么与他关联的都会自动同步
        //一个套接字绑定一个 io_service 对象，套接字的读和写可以并发执行(tcp是全双工通信)

        //所以设置几个线程是根据系统的承载能力

        int thread_count = std::thread::hardware_concurrency();
        if(thread_count == 0)
        {
            thread_count = 2;
        }

        boost::asio::io_service ioc;

        boost::asio::strand<boost::asio::io_service::executor_type> strand_log = boost::asio::make_strand(ioc);//用来同步日志输出

        server server_(
                ioc
                , strand_log
                , vm["port"].as<short>()
                , vm["remoteipv4"].as<std::string>()
                , vm["remoteport"].as<short>()
                , vm["verbose"].as<short>()
                );
        server_.start();

//        boost::asio::deadline_timer dt(ioc);
//        dt.expires_from_now(boost::posix_time::seconds(5));
//        auto handler = [&](boost::system::error_code error){
//            if(!error)
//            {
//                std::cout << "overtime" << "\n";

//                return;
//            }
//            else if(error == boost::asio::error::operation_aborted)//被cancel  调用cancel()或者重新设置超时时间
//            {
//                std::cout << "cancel" << "\n";
//            }
//            else
//            {
//                std::cout << "other" << "\n";
//            }
//        };
//        dt.async_wait(handler);
//        dt.expires_from_now(boost::posix_time::seconds(6));


        std::vector<std::shared_ptr<std::thread>> tv(thread_count);
        for(int i = 0; i < thread_count; ++i)
        {
            tv[i] = std::make_shared<std::thread>(
                [&ioc](void){
                    for(;;)
                    {
                        try {
                            ioc.run();
                            break;
                        } catch (...) {}
                    }
                }
            );
        }
        for(auto& t : tv)
        {
            t->join();
        }
    }
    catch (std::exception& e)
    {
        write_log(log_level_error, 0, -1, "", e.what());
    }
    catch (...)
    {
        write_log(log_level_error, 0, -1, "", "exception...");
    }

    return 0;
}
