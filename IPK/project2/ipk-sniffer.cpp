/** Project: IPK Packet sniffer **/
/** File: ipk-sniffer.cpp      **/
/** Author: Lukas Foltyn       **/

#include "packet_info.h"
#include <getopt.h>
#include <signal.h>

/* global variables */
pcap_t *descr; // Network interface
bpf_program filter; // Filter for packets

/**
* @brief function that tries to convert string to number, exits on failure
* @param string_to_convert string that's being converted to a number
* @return int - converted number
**/
int STI_exit_on_error(char *string_to_convert)
{
    size_t idx{};
    int converted_number{};
    try
    {
        converted_number = std::stoi(string_to_convert,&idx,10);
    }
    catch(const std::exception& e)
    {
        std::cerr << "Invalid number '"<< string_to_convert <<"' as argument. Integer is required." << '\n';
        return 1;
    }
    // string contains some text as well -> invalid
    if(idx != strlen(string_to_convert))
    {
        std::cerr << "Invalid number '"<< string_to_convert <<"' as argument. Integer is required." << '\n';
        return 1;
    }
    return converted_number;
}

/**
* @brief function that adds new filter option to the filter string, if not contained
* @param filter_str string that's being updated with new option
* @param option string represnting filter option that's being added
**/
void add_filter_option(std::string & filter_str, std::string option)
{
    if(filter_str.empty())
    {
        filter_str.append(option);
    }
    else if(filter_str.find(option) == std::string::npos)
    {
        filter_str.append(" or " + option);
    }
}

/**
* @brief function that prints out the usage of this program
**/
void usage_print()
{
    using namespace std;
    cerr << "Usage: ./ipk-sniffer [-i rozhraní | --interface rozhraní]";
    cerr << " {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}" << endl;
}

/**
* @brief function that frees all the resources used from libcap library
**/
void clear_up()
{
    pcap_freecode(&filter);
    pcap_close(descr);
}

/**
* @brief function that's called (after user presses CTR-C) for freeing resources
**/
void signal_handler(int sig)
{
    clear_up();
    exit(sig);
}

/**
* @brief function that receives a packet from libcap function and prints it to stdout
* @param user data passed by user
* @param header pcap_pkthdt structure containing the lenght of the packet a it's timestamp
* @param packet_data pointer to whole packet represented as byte array
**/
void packet_handler(u_char * user, const pcap_pkthdr * header, const u_char* packet_data)
{
    PacketInfo packet { packet_data, header };
    packet.print_packet();
}


int main(int argc, char **argv)
{
    using namespace std;


    // determines how many packets should be displayed
    // default value is one
    int packets_to_display{1};

    // port where to filter packets
    // default is 0 --> can be any port
    int port{0};

    // intereface given by user
    string interface{};

    // filter options
    string filter_options{};

    // long options
    option long_options[]{
        {"tcp", no_argument, 0, 't'},
        {"udp", no_argument, 0, 'u'},
        {"arp", no_argument, 0, 'a'},
        {"icmp", no_argument, 0, 'c'},
        {"interface", optional_argument,0, 'i'}
    };

    // turning off the getopt error messages
    opterr = 0;

    // character for getopt return value
    int c{};

    while((c = getopt_long(argc, argv, "i::n::p::tu", long_options, nullptr))!= -1)
    {
        switch (c)
        {
            case 'a':
                add_filter_option(filter_options, "arp");
                break;
            case 'c':
                add_filter_option(filter_options, R"(protochain \icmp or icmp6)");
                break;
            case 'i':
                if(optarg)
                {
                    interface = optarg;
                }
                else if(optind < argc)
                {
                    // next argument is not an option
                    if(argv[optind][0] != '-')
                    {
                        interface = argv[optind++];
                    }
                }
                break;
            case 'n':
                if(optarg)
                {
                    packets_to_display = STI_exit_on_error(optarg);
                }
                // if there is argument, it can not be option
                else if(optind < argc && argv[optind][0] != '-')
                {
                    packets_to_display = STI_exit_on_error(argv[optind++]);
                }
                else
                {
                    cerr << "'-n' option requires an argument." << endl;
                    return 1;
                }
                break;
            case 't':
                add_filter_option(filter_options, R"(protochain \tcp)");
                break;
            case 'u':
                add_filter_option(filter_options, R"(protochain \udp)");
                break;
            case 'p':
                if(optarg)
                {
                    port = STI_exit_on_error(optarg);
                }
                // if there is argument, it can not be option
                else if(optind < argc && argv[optind][0] != '-')
                {
                    port = STI_exit_on_error(argv[optind++]);
                }
                else
                {
                    cerr << "'-p' option requires an argument." << endl;
                    return 1;
                }
                break;
            case '?':
                usage_print();
                return 1;

            default:
                cerr << "An error occurred while parsing."<< endl;
                return 1;
        }

    }
    while(optind < argc)
    {
        cerr << "Unknown argument given: '" << argv[optind++] << "'" << endl;
    }

    if(packets_to_display == 0)
    {
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE]; // Buffer for error message
    pcap_if_t *dev; // Network devices
    bpf_u_int32 mask; // Subnet mask
    bpf_u_int32 netaddr; // Ip

    // when CTRL-C is pressed to exit program
    // resources needs to be freed
    signal(SIGINT, signal_handler);

    // setting protocol filter options
    if(filter_options.empty())
    {
        filter_options.append(R"(protochain \tcp or protochain \udp or protochain \icmp or icmp6 or arp)");
    }

    // setting port filter option
    if(port)
    {
        filter_options.append(" and port " + to_string(port));
    }

    // list all available network devices and exit
    if(interface.empty())
    {
        if(pcap_findalldevs(&dev, errbuf) != 0)
        {
            cerr << "pcap_findalldevs(): " << errbuf << endl;
            return 1;
        }
        pcap_if_t * temp = dev;
        while(temp != nullptr)
        {
            cout << temp->name << endl;
            temp = temp->next;
        }
        pcap_freealldevs(dev);
        return 0;
    }

    // open connection for receiving packets
    descr = pcap_open_live(interface.c_str(), MAXBYTES2CAPTURE, 1, 512, errbuf);
    if(descr == nullptr)
    {
        cerr << "pcap_open_live(): " << errbuf << endl;
        return 1;
    }

    // get mask and network address of an interface
    if(pcap_lookupnet(interface.c_str(), &netaddr, &mask, errbuf) == -1)
    {
        cerr << "pcap_lookupnet(): " << errbuf << endl;
        pcap_close(descr);
        return 1;
    }

    // create filter
    if(pcap_compile(descr,&filter, filter_options.c_str(), 0, mask) == -1)
    {
        cerr << "pcap_compile(): " << pcap_geterr(descr) << endl;
        pcap_close(descr);
        return 1;
    }

    // set filter
    freopen("/dev/null", "w", stderr);
    if(pcap_setfilter(descr,&filter) == -1)
    {
        fclose(stderr);
        cerr << "pcap_setfilter(): " << pcap_geterr(descr) << endl;
        clear_up();
        return 1;
    }
    fclose(stderr);

    // wait for packets and process them in packet_handler function
    if(pcap_loop(descr, packets_to_display, packet_handler, 0) == -1)
    {
        cerr << "pcap_loop(): " << pcap_geterr(descr) << endl;
        clear_up();
        return 1;
    }

    clear_up();
    return 0;
}
