# portClassifier
Handy with entry pcap analysis 
usage: srcportcounterV2.py [-h] [--target_ip TARGET_IP] [--target] [--ports_db PORTS_DB] pcap_file

python3 srcportcounterV2.py example.pcap.00 --target
{
  List of SRC and DST ports (top10) and top5 targets
}

python3 srcportcounterV2.py example.pcap.00 --target_ip {some ip}
{
  List of SRC and DST ports (top10) where targetip is {some ip}
}
