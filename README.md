# TPlink_conf_decryptor_uncompressor
A little python script to decrypt TPlink conf.bin file.

Script originally written by DuSu, Modifiied by DrmnSamoLiu for python3 compatibility.

Tested on my TPlink Archer C20.

## Notice
You will need a `libcutil.so` from the firmware your device is running in the same directory as this script, it can usaully be obtained under `/lib` directory in the unpacked firmware file.

Change the value of  `UNCOMP_END_OFFSET` on line 46 to offset that match the `jr $ra` operation in your `libcutil.so` and everything should work fine.

## Alternative
This script uses `angr` to emulate the decompression algorithm, however there is another script written by ` sta-c0000 ` who actually reverse engineered the whole algorithm which makes it more straight forward and doesn't require `angr` to run.
You can find the script here: https://github.com/sta-c0000/tpconf_bin_xml 
