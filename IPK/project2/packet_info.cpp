/** Project: IPK Packet sniffer **/
/** File: packet_info.cpp      **/
/** Author: Lukas Foltyn       **/

#include "packet_info.h"
#include "defined_headers.h"


std::string PacketInfo::get_source_ip() const
{
    const u_char *offset { PacketInfo::get_network_header() };

    char src_ip_string[50];

    switch (PacketInfo::get_network_protocol())
    {
        case ETHERTYPE_ARP:
        {
            uint32_t src_ip{ ((arphdr_t *) offset)->spa };
            std::sprintf(src_ip_string, "%d.%d.%d.%d", P1_IPV4(src_ip) , P2_IPV4(src_ip), P3_IPV4(src_ip), P4_IPV4(src_ip));
            return src_ip_string;
        }
        case ETHERTYPE_IP:
            return std::string(inet_ntoa(((ip*) offset)->ip_src));
        case ETHERTYPE_IPV6:
            inet_ntop(AF_INET6, &(((ip6_hdr*) offset)->ip6_src), src_ip_string, INET6_ADDRSTRLEN);
            return src_ip_string;
        default:
            throw UnexpectedProtocol();
    }
}

std::string PacketInfo::get_destination_ip() const
{
    const u_char *offset { PacketInfo::get_network_header() };

    char dst_ip_string[50];
   
    switch (PacketInfo::get_network_protocol())
    {
        case ETHERTYPE_ARP:
        {
            uint32_t dst_ip{ ((arphdr_t *) offset)->tpa };
            std::sprintf(dst_ip_string, "%d.%d.%d.%d", P1_IPV4(dst_ip), P2_IPV4(dst_ip), P3_IPV4(dst_ip), P4_IPV4(dst_ip));
            return dst_ip_string;
        }
        case ETHERTYPE_IP:
            return std::string(inet_ntoa(((ip*) offset)->ip_dst));
        case ETHERTYPE_IPV6:
            inet_ntop(AF_INET6, &(((ip6_hdr*) offset)->ip6_dst), dst_ip_string, INET6_ADDRSTRLEN);
            return dst_ip_string;
        default:
            throw UnexpectedProtocol();
    }
}

std::string PacketInfo::get_timestamp() const
{
    char current_time[30];
    tm * time_struct {localtime(&pcap_header->ts.tv_sec)};

    std::strftime(current_time, 30,"%FT%T" , time_struct);
    return current_time + ('.' + std::to_string(pcap_header->ts.tv_usec/1000)) + (strcmp(time_struct->tm_zone,"CEST") ? "+2:00" : "+1:00");
}

uint16_t PacketInfo::get_network_protocol() const
{
    ether_header *ethr { (ether_header*) packet_data };
    return ntohs(ethr->ether_type);
}

uint8_t PacketInfo::get_transport_protocol() const
{
    const u_char *offset { PacketInfo::get_network_header() };

    switch (PacketInfo::get_network_protocol())
    {
        case ETHERTYPE_IP:
        {
            const u_char * min_offset{ offset + ((ip*)offset)->ip_hl * 4 };
            if(((ip*)offset)->ip_p == IPPROTO_ESP)
                throw UnexpectedProtocol();
            else if(((ip*)offset)->ip_p == IPPROTO_AH)
                return ((ahhdr_t*)min_offset)->nxt_hdr;
            else
                return ((ip*)offset)->ip_p;
        }
        case ETHERTYPE_IPV6:
        {
            uint8_t next_header = ((ip6_hdr *)offset)->ip6_ctlun.ip6_un1.ip6_un1_nxt;
            offset += sizeof(ip6_hdr);
            while(true)
            {
                switch (next_header)
                {
                    case IPPROTO_HOPOPTS:
                        next_header = ((ip6_hbh*)offset)->ip6h_nxt;
                        offset += (((ip6_hbh*)offset)->ip6h_len << QUADWORD_TO_BYTES_SHIFT) + EIGHT_OCTETS;
                        break;
                    case IPPROTO_ROUTING:
                        next_header = ((ip6_rthdr*)offset)->ip6r_nxt;
                        offset += (((ip6_rthdr*)offset)->ip6r_len << QUADWORD_TO_BYTES_SHIFT) + EIGHT_OCTETS;
                        break;
                    case IPPROTO_FRAGMENT:
                        next_header = ((ip6_frag*)offset)->ip6f_nxt;
                        offset += sizeof(ip6_frag);
                        break;
                    case IPPROTO_DSTOPTS:
                        next_header = ((ip6_dest*)offset)->ip6d_nxt;
                        offset += (((ip6_dest*)offset)->ip6d_len << QUADWORD_TO_BYTES_SHIFT) + EIGHT_OCTETS;
                        break;
                    case IPPROTO_AH:
                        next_header = ((ahhdr_t*)offset)->nxt_hdr;
                        offset += ((((ahhdr_t*)offset)->pld_len)  << DOUBLEWORD_TO_BYTES_SHIFT) + EIGHT_OCTETS;
                        break;
                    case IPPROTO_ESP:
                    case IPPROTO_NONE:
                        throw UnexpectedProtocol();
                    default:
                        return next_header;
                }
            }
        }
        default:
            throw UnexpectedProtocol();
    }
}

const u_char * PacketInfo::get_network_header() const
{
    return packet_data + sizeof(ether_header);
}

const u_char * PacketInfo::get_transport_header() const
{
    const u_char *offset { PacketInfo::get_network_header() };

    switch (PacketInfo::get_network_protocol())
    {
        case ETHERTYPE_IP:
        {
            const u_char * min_offset{ offset + ((ip*)offset)->ip_hl * 4 };
            if(((ip*)offset)->ip_p == IPPROTO_ESP)
                throw UnexpectedProtocol();
            else if(((ip*)offset)->ip_p == IPPROTO_AH)
                return min_offset+(((ahhdr_t*)min_offset)->pld_len << DOUBLEWORD_TO_BYTES_SHIFT) + EIGHT_OCTETS;
            else
                return min_offset;
        }
        case ETHERTYPE_IPV6:
        {
            uint8_t next_header = ((ip6_hdr *)offset)->ip6_ctlun.ip6_un1.ip6_un1_nxt;
            offset += sizeof(ip6_hdr);
            while(true)
            {
                switch (next_header)
                {
                    case IPPROTO_HOPOPTS:
                        next_header = ((ip6_hbh*)offset)->ip6h_nxt;
                        offset += (((ip6_hbh*)offset)->ip6h_len << QUADWORD_TO_BYTES_SHIFT) + EIGHT_OCTETS;
                        break;
                    case IPPROTO_ROUTING:
                        next_header = ((ip6_rthdr*)offset)->ip6r_nxt;
                        offset += (((ip6_rthdr*)offset)->ip6r_len << QUADWORD_TO_BYTES_SHIFT) + EIGHT_OCTETS;
                        break;
                    case IPPROTO_FRAGMENT:
                        next_header = ((ip6_frag*)offset)->ip6f_nxt;
                        offset += sizeof(ip6_frag);
                        break;
                    case IPPROTO_DSTOPTS:
                        next_header = ((ip6_dest*)offset)->ip6d_nxt;
                        offset += (((ip6_dest*)offset)->ip6d_len << QUADWORD_TO_BYTES_SHIFT) + EIGHT_OCTETS;
                        break;
                    case IPPROTO_AH:
                        next_header = ((ahhdr_t*)offset)->nxt_hdr;
                        offset += ((((ahhdr_t*)offset)->pld_len) << DOUBLEWORD_TO_BYTES_SHIFT) + EIGHT_OCTETS;
                        break;
                    case IPPROTO_ESP:
                    case IPPROTO_NONE:
                        throw UnexpectedProtocol();
                    default:
                        return offset;
                }
            }
        }
        default:
            throw UnexpectedProtocol();
    }
}

std::string PacketInfo::get_source_port() const
{
    const u_char * offset;
    uint8_t protocol;

    try
    {
        protocol = PacketInfo::get_transport_protocol();
        offset = get_transport_header();
    }
    catch (UnexpectedProtocol & e)
    {
            return {"no port"};
    }
    if(protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
        return {"no port"};

    return std::to_string(protocol == IPPROTO_UDP  ? ntohs(((udphdr*)offset)->uh_sport) : ntohs(((tcphdr*)offset)->th_sport));


}

std::string PacketInfo::get_destination_port() const
{
    const u_char * offset;
    uint8_t protocol;

    try
    {
        protocol = PacketInfo::get_transport_protocol();
        offset = get_transport_header();
    }
    catch (UnexpectedProtocol & e)
    {
            return {"no port"};
    }
    if(protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
        return {"no port"};

    return std::to_string(protocol == IPPROTO_UDP  ? ntohs(((udphdr*)offset)->uh_dport) : ntohs(((tcphdr*)offset)->th_dport));
}

void PacketInfo::print_packet() const
{
    using namespace std;

    size_t print_start{};
    size_t print_end{};

    ios_base::fmtflags format{ cout.flags() };

    try
    {
        cout << PacketInfo::get_timestamp() << ' ' << PacketInfo::get_source_ip() << " : " << PacketInfo::get_source_port();
        cout << " > " << PacketInfo::get_destination_ip() <<" : " << PacketInfo::get_destination_port();
        cout << ", lenght " << pcap_header->caplen << endl;
    }
    catch(const UnexpectedProtocol& e)
    {
        cerr << e.what() << endl;
    }

    while(print_end != pcap_header->caplen)
    {
        print_start = print_end;
        print_end = (print_end + ONE_L_LENGHT > pcap_header->caplen ? pcap_header->caplen : print_end + ONE_L_LENGHT);

        cout << "0x" << setw(4) << setfill ('0') << hex << print_start << ":  ";

        for (size_t hex_c = print_start; hex_c < print_end; hex_c++)
        {
            cout << setw(2) << setfill('0') << hex << (0xff & packet_data[hex_c]) << ' ';
            if(hex_c == print_start + 7)
                cout << ' ';
        }

        cout.flags(format);

        if(print_end == pcap_header->caplen)
        {
            size_t characters_to_end { ONE_L_LENGHT - (print_end - print_start) };
            size_t spaces_to_print { characters_to_end * 3 + static_cast<size_t>(characters_to_end > 8 ? 1 : 0) };
            while (spaces_to_print--)
            {
                cout << ' ';
            }
        }

        for (size_t char_c = print_start; char_c < print_end; char_c++)
        {
            cout << static_cast<unsigned char>(isprint(packet_data[char_c]) ? packet_data[char_c] : '.');
            if(char_c == print_start + 7)
                cout << ' ';
        }

        cout << endl;
    }

    cout << endl;
}
