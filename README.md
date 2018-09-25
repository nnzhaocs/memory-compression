# memory-compression

## Environment & Dependencies:
- Memory compression is implemented on Ubuntu version `acelan/linux-stable.git` as shown at `http://kernel.ubuntu.com/git/acelan/linux-stable.git/`. 
- Please download the linux kernel as follows:
`git clone git://kernel.ubuntu.com/acelan/linux-stable.git`
## How to run this code?
### Applying the changes
- Directory `linux-stable-cmask/` contains all the files that I modified or added.
- Apply the diff to directory `linux-stable/` you just download.
`patch -s -p0 < changes.patch`
### Building the kernel
- Build your customized kernel using the commands below:

    ```cp /boot/config-`uname -r` .config```
    
    ```make -j `getconf _NPROCESSORS_ONLN` deb-pkg LOCALVERSION=-custom-cmask```
    
        If there is problem, try: 
        
        `sudo apt-get install -y chrpath gawk texinfo libsdl1.2-dev whiptail diffstat cpio libssl-dev`
        
    `yes '' | make oldconfig`
    
    `make clean`

    `cd ..`

    `sudo dpkg -i linux-*4.3*.deb`

- Reserve RAM area for compression buffer:

    Add or append an entry to `/etc/default/grub`: `GRUB_CMDLINE_LINUX="memmap=4K!4G"`

    Use `dmesg` to see reserved ranges
        
- Reboot your machine and choose your new kernel in grub. Now you are using your new kernel.
    
    `sudo reboot`
    
## Test system calls
- sys_cmask_insert_SPP_to_IAL is implemented to insert SPP to Indirectly addressable location. 

      insert_SPP_to_indirectly_addressable_location_ISR:
        INPUTS: A) swap address of the SPP
        Precondition: The OS has copied the secondary page’s values into a 4KB compression buffer in memory 
        Postcondition: For the modified hardware, CPU compresses the data in SRB and writes data to the indirectly address
        location by ignoring the ISR’s body. For the traditional hardware, ISR reads SRB’s data and writes them to the input
        swap address. NANNAN: modified hardware will return 0; while traditional hardware will return 1.
        
        Run the following command and get the messages printed by `printk` function in the system call:
        `sudo dmesg -c`
        
