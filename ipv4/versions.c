const char* get_ip_version(int code){
 switch (code) {
        case 0:
            return "Internet Protocol, pre-v4";

        case 4:
            return "Internet Protocol version 4 (IPv4)";

        case 5:
            return "Internet Stream Protocol (ST / ST-II)";

        case 6:
            return "Internet Protocol version 6 (IPv6)";

        case 7:
            return "TP/IX The Next Internet (IPv7)";

        case 8:
            return "P Internet Protocol (PIP)";

        case 9:
            return "TCP and UDP over Bigger Addresses (TUBA)";

        case 15:
            return "Version field sentinel value";

        default:
            return "Unknown or unsupported IP version";
    }
}
