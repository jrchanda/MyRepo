host_dict = {'00:F6:63:DA:6E:0C': 'VIC-MLOM-eth0', '00:F6:63:DA:6E:10': 'modified_eth_dev_1MLOM', '2C:33:11:44:11:C4': 'LOMPort1', '2C:33:11:44:11:C5': 'LOMPort2', '00:F6:63:DA:6E:0D': 'VIC-MLOM-eth1'}
cimc_dict = {'00:F6:63:DA:6E:0D': 'VIC-MLOM-eth1', '00:F6:63:DA:6E:10': 'cdn_eth_dev_1MLOM', '00:F6:63:DA:6E:0C': 'VIC-MLOM-eth0', '00:F6:63:DA:6E:11': 'cdn_eth_dev_2MLOM', '00:F6:63:DA:6E': 'VIC-MLOM-eth'}
       
def verify():     
    match = True
    for key in cimc_dict.keys():
        if key in host_dict.keys():
            if cimc_dict[key] != host_dict[key]:
                print('After OS boot, CDN name set from CIMC CLI and Host are not same')
                print('CDN name from CIMC:' +cimc_dict[key] + ' Host CDN: ' + host_dict[key])
                match = False
            else:
                print('After OS boot, CDN name set from CIMC CLI and Host are remains same')
                print('Configure CDN name from CIMC: ' +cimc_dict[key] + ' Host CDN: ' + host_dict[key])
    if match is True:
        return True
    else:
        return False

if __name__ == '__main__':
    out = verify()
    print(out)