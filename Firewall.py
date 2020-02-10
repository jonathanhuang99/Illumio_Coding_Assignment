import csv

class Firewall:
    """
    This class is responsible for accepting/rejecting connections.
    """

    def __init__(self, inputFile):
        """
        The Firewall class is initialized with a file path and a dictionary of rules. The dictionary is initialized with the four
        possible combinations of direction and protocol as keys to reduce time complexity. Each of those keys contain a list of two dictionaries.
        The first dictionary is for ports and the latter is for ip addresses. There will be two keys: single and range. The first single
        key will contain a set of singular items such as one port or one ip address and the second key will contain a range of items such
        as a range of ports or a range of ip addresses.
        """
        self.inputFile = inputFile
        self.rules = {('inbound','tcp'): [{'single': set(), 'range': set()}, {'single': set(), 'range': set()}],
                      ('inbound','udp'): [{'single': set(), 'range': set()}, {'single': set(), 'range': set()}],
                      ('outbound','tcp'): [{'single': set(), 'range': set()}, {'single': set(), 'range': set()}],
                      ('outbound','udp'): [{'single': set(), 'range': set()}, {'single': set(), 'range': set()}]
                      }

    def process_rules(self) -> None:
        """
        This function opens up the csv file and adds the rules to a dictionary which
        already prefilters the 4 possible combinations of direction and protocol.
        """
        with open(self.inputFile, 'r') as file: ## Skip the column header while reading a csv file https://evanhahn.com/python-skip-header-csv-reader/
            reader = csv.reader(file)
            next(reader)
            for row in reader:
                key = (row[0],row[1])
                if('-' in row[2]):
                    self.rules[key][0]['range'].add(row[2])
                else:
                    self.rules[key][0]['single'].add(int(row[2]))
                if('-' in row[3]):
                    self.rules[key][1]['range'].add(row[3])
                else:
                    self.rules[key][1]['single'].add(row[3])

    def accept_packet(self, direction: str, protocol: str, port: int, ip_address: str) -> bool:
        """
        This function checks if the direction, protocol, port, and ip address match any of the rules.
        """
        def basic_check(direction: str, protocol: str, port: int, ip_address: str) -> bool:
            """
            Checks if the packet meets the basic requirements.
            """
            if direction not in {'inbound', 'outbound'}:
                return False
            if protocol not in {'tcp','udp'}:
                return False
            if not (1 <= port <= 65535):
                return False
            ip = ip_address.split('.')
            for octet in ip:
                if not (0<=int(octet)<=255):
                    return False
            return True
        def valid_port(direction: str, protocol: str, port: int, ip_address: str) -> bool:
            """
            Checks if the port exists in the single set which only contains indiviual ports. If it is not in there,
            it checks inside the set of ranges to see if the port exists within there.
            """
            key = (direction,protocol)
            if port in self.rules[key][0]['single']:
                return True
            else:
                for port_range in self.rules[key][0]['range']:
                    p_ranges = port_range.split('-')
                    startPort = int(p_ranges[0])
                    endPort = int(p_ranges[1])
                    if startPort <= port <= endPort:
                        return True
            return False

        def valid_ip(direction: str, protocol: str, port: int, ip_address: str) -> bool:
            """
            Checks if the ip address exists in the single set which only contains indiviual ip addresses. If it is not in there,
            it checks inside the set of ranges to see if the ip address exists within there.
            """
            key = (direction,protocol)
            if ip_address in self.rules[key][1]['single']:
                return True
            else:
                for ip in self.rules[key][1]['range']:
                    ip_address = tuple(ip_address.split('.'))
                    ip_address_ranges = ip.split('-')
                    startIP = tuple(ip_address_ranges[0].split('.'))
                    endIP = tuple(ip_address_ranges[1].split('.'))
                    if startIP <= ip_address <= endIP:
                        return True
            return False
        if basic_check(direction, protocol, port, ip_address) == False: ## If the direction, protocol, port, or ip address fail the basic criteria, return False.
            return False
        return (valid_port(direction, protocol, port, ip_address) and valid_ip(direction, protocol, port, ip_address))

if __name__ == "__main__":

    fw = Firewall('rules.csv')
    fw.process_rules()
    print("-------Sample Test Cases-------")
    print(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
    print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"))
    print(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"))
    print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
    print(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"))
    
    print("-------My Test Cases-------") ## Rule 3
    print(fw.accept_packet("outbound", "tcp", 9999, "192.168.10.11")) ## False
    print(fw.accept_packet("outbound", "tcp", 10000, "192.168.10.11")) ## True
    print(fw.accept_packet("outbound", "tcp", 15000, "192.168.10.11")) ## True
    print(fw.accept_packet("outbound", "tcp", 20000, "192.168.10.11")) ## True
    print(fw.accept_packet("outbound", "tcp", 20001, "192.168.10.11")) ## False
    
    print("\n-----------------------------------------------\n") ## Rule 4
    print(fw.accept_packet("inbound", "udp", 53, "192.168.1.0")) ## False
    print(fw.accept_packet("inbound", "udp", 53, "192.168.1.1")) ## True
    print(fw.accept_packet("inbound", "udp", 53, "192.168.1.9")) ## True
    print(fw.accept_packet("inbound", "udp", 53, "192.168.2.0")) ## True
    print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1")) ## True
    print(fw.accept_packet("inbound", "udp", 53, "192.168.2.5")) ## True
    print(fw.accept_packet("inbound", "udp", 53, "192.168.2.6")) ## False
    print(fw.accept_packet("inbound", "udp", 53, "192.168.3.0")) ## False
    
    print("\n-----------------------------------------------\n") ## Rule 5
    print(fw.accept_packet("outbound", "udp", 999, "52.12.48.92")) ## False
    print(fw.accept_packet("outbound", "udp", 1000, "52.12.48.92")) ## True
    print(fw.accept_packet("outbound", "udp", 1500, "52.12.48.92")) ## True
    print(fw.accept_packet("outbound", "udp", 2000, "52.12.48.92")) ## True
    print(fw.accept_packet("outbound", "udp", 2001, "52.12.48.92")) ## False

    print("\n-----------------------------------------------\n") ## Rule 6
    print(fw.accept_packet("inbound", "tcp", 81, "-1.-1.-1.-1")) ## False
    print(fw.accept_packet("inbound", "tcp", 81, "255.255.255.255")) ## True
    print(fw.accept_packet("inbound", "tcp", 81, "256.256.256.256")) ## False
    
    print("\n-----------------------------------------------\n") ## Rule 7
    print(fw.accept_packet("outbound", "udp", 77, "199.169.1.1")) ## True
    print(fw.accept_packet("outbound", "udp", 77, "198.169.1.1")) ## True
    print(fw.accept_packet("outbound", "udp", 77, "201.169.1.1")) ## False
    print(fw.accept_packet("outbound", "udp", 77, "192.168.1.1")) ## True
    print(fw.accept_packet("outbound", "udp", 77, "201.0.0.0")) ## True
    

    

    

