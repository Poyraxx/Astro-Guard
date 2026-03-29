@echo off
echo Remote Attack Node examples
echo.
echo Normal:
echo python remote_signal_client.py --host 192.168.1.50 --port 9000 --protocol udp --mode normal --count 3 --satellite-profile turksat-6a
echo.
echo Mission breach:
echo python remote_signal_client.py --host 192.168.1.50 --port 9000 --protocol udp --mode mission-breach --count 2 --satellite-profile turksat-6a
echo.
echo Shadow contact:
echo python remote_signal_client.py --host 192.168.1.50 --port 9000 --protocol udp --mode shadow-contact --count 2 --satellite-profile turksat-6a
