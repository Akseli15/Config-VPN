sar -u 1 1 | tail -n 1 | awk '{print 100 - $8}'
sudo wg