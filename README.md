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
    `make mrproper`

    `make menuconfig`

    `make bzImage`

    `make modules`

    `sudo make modules_install`

    `sudo make install`

- Reboot your machine and choose your new kernel in grub. Now you are using your new kernel.
## Test system calls.
- sys_cmask_insert_SPP_to_IAL is implemented to insert SPP to Indirectly addressable location. 

      insert_SPP_to_indirectly_addressable_location_ISR:
        INPUTS: A) swap address of the SPP
        Precondition: The OS has copied the secondary page’s values into a 4KB compression buffer in memory 
        Postcondition: For the modified hardware, CPU compresses the data in SRB and writes data to the indirectly address
        location by ignoring the ISR’s body. For the traditional hardware, ISR reads SRB’s data and writes them to the input
        swap address. NANNAN: modified hardware will return 0; while traditional hardware will return 1.
