#include "s5p.h"

#include <thread>

#include <boost/locale.hpp>
#include <boost/program_options.hpp>

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
                ("buffersize,b",boost::program_options::value<unsigned>()->default_value(196608),"data buffer size")
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


        boost::asio::io_service ioc;
        Server server(ioc, vm["port"].as<short>(), vm["buffersize"].as<unsigned>(), vm["verbose"].as<short>(), vm["remoteipv4"].as<std::string>(), vm["remoteport"].as<short>());


        int tnum = std::thread::hardware_concurrency();
        if(tnum==0)
        {
            tnum=2;
        }
        std::vector<std::shared_ptr<std::thread>> tv(tnum);
        for(auto& t : tv)
        {
            t = std::make_shared<std::thread>(
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
        //write_log(1, 0, vm["verbose"].as<short>(), -1, "", e.what());
    }
    catch (...)
    {
        //write_log(1, 0, vm["verbose"].as<short>(), -1, "", "exception...");
    }

    return 0;
}
