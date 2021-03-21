

#include "TrafficGenerator/logic/DpdkClient.h"
#include "TrafficGenerator/ArgumentParser.h"

#include <iostream>


void PrintUsage() {
    std::cout << "Usage:" << std::endl << std::endl;
    std::cout << pcpp::AppName::get() << "  -d <dpdk_port> [-r <rx_queue_amount>] [-t <tx_queue_amount>]" << std::endl
              << std::endl;
    std::cout << "Options:" << std::endl << std::endl;
    std::cout << "  -d --dpdk-port <dpdk_port>          : DPDK Port ID" << std::endl;
    std::cout << "  -r --rx-queues <rx_queue_amount     : Amount of RX queues to be opened" << std::endl;
    std::cout << "  -t --tx-queues <tx_queue_amount     : Amount of TX queues to be opened" << std::endl;
    std::cout << "  -h --help                           : Displays this help message" << std::endl;
}


void ParseArgs(int argc, char *argv[], DpdkService::DpdkServiceArgs &args) {
    ArgumentParser parser(argc, argv);

    if (!parser.OptionExists("-d")) {
        std::cerr << "DPDK port flag is mandatory (-d <dpdk_port>)" << std::endl;
        std::exit(1);
    }

    std::string port = parser.GetOption("-d");
    args.m_DpdkPortId = std::stoi(port);

    if (parser.OptionExists("-h")) {
        PrintUsage();
        std::exit(0);
    }

    if (parser.OptionExists("-b"))
        args.m_MaxBurstSize = std::stoul(parser.GetOption("-b")) & 0xFFFF;
    if (parser.OptionExists("-r"))
        args.m_RxQueues = std::stoul(parser.GetOption("-r")) & 0xFFFF;
    if (parser.OptionExists("-t"))
        args.m_TxQueues = std::stoul(parser.GetOption("-t")) & 0xFFFF;
}


int main(int argc, char *argv[]) {
    try {
        DpdkService::DpdkServiceArgs args;
        ParseArgs(argc, argv, args);

        args.m_DhcpEnabled = false;
        args.m_ClientIpAddress = "10.100.102.29";
        args.m_ServerIpAddress = "10.100.102.30";

        DpdkClient service(args);

        bool running = true;

        while (running) {
            std::cout << "TrafficGenerator# ";
            std::string input;
            std::getline(std::cin, input);
            if (input == "start")
                service.Start();
            if (input == "send")
                if (service.Running())
                    service.EnableSending();
            if (input == "close") {
                if (service.Running())
                    service.Close();
            }
            if (input == "exit") {
                if (service.Running())
                    service.Close();
                running = false;
            }
        }
    }

    catch (const DpdkService::DpdkInitializationError &e) {
        std::cerr << e.what() << std::endl;
    }
    catch (const DpdkService::UnknownDeviceException &e) {
        std::cerr << e.what() << std::endl;
    }
    catch (const DpdkService::MultiQueueException &e) {
        std::cerr << e.what() << std::endl;
    }
    catch (const DpdkService::InvalidIpAddressException &e) {
        std::cerr << e.what() << std::endl;
    }
    catch (const DpdkService::EmptyLogFileNameException &e) {
        std::cerr << e.what() << std::endl;
    }
    catch (const DpdkService::LogFileException &e) {
        std::cerr << e.what() << std::endl;
    }
    catch (const std::exception &e) {
        std::cerr << "UNHANDLED EXCEPTION CAUGHT: " << e.what() << std::endl;
    }
}