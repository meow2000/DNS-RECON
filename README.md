# DNS-RECON
  A reconniassanse tool to find both public and private Internet Protocol(IP) on selected target and perform automation audit. This tool helps to grab all dns both public and private IPs also perform reverse dns to locate dns PTR records for that IPs.



  # DNS and Reverse DNS Automating w/ report logs
    Enter a single IP address or domain, or select either a list of IP addresses or domains to be submitted for DNS or Reverse DNS lookups.  You can also specify an option to output the results to text file "report.txt"

  # Command-line options

  usage: dns_lookup -h -u -l -o -d [DNS] -rv [R-DNS] -v

Python DNS and reverse DNS lookup by: Cypher

options:
  -h, --help            show this help message and exit
  -u, --url             indicate as input
  -l, --list            Indicate list Input
  -o, --output          A output report
  -d DNS, --dns DNS     DNS Lookup
  -rv RDNS, --rdns RDNS
                        For reverse DNS
  -v, --verssion        Show program verssion
