# Rootkits Design Doc
Names: Matthew Ta (z5061797), Francis Dong (z5118740), Marmik Panchal (z5060470) and Pranav Bhatia (z5059799)
Date: 29/09/2018

# Installation:
* Our install script creates a folder called "stash" and then transfers all the
scripts over to the directory.
* Make is then executed which compiles our rootkit producing rootkit.kld.
* The kld file is then loaded into the kernel using the command "kldload".
* Once this is done, all the files are removed as they are no longer required.

# Privilege Escalation:
* To escalate from user (comp6447) privileges to root privileges, we have decided to hook the write() syscall.
* After running ktrace echo “hello world” and then following up with kdump, we observed that the command calls write(0x1, <user space addr>, size) or some variation of write() that ends up calling write().
* The hooked write() syscall will listen for the following string "superrandompasswordthatonlytheselectfewknow9875" and if this string is received and destined for file descriptor 1 (STDOUT) then the hook will look into the current thread and acquire the pointer to the proc structure. Once the hook has a pointer to the proc structure of the thread that called write() then it will also look into the proc pointer to acquire the ucred field. The ucred field contains the credentials and privileges for the process and by setting the cr_uid field of this structure to 0, the privileges of the calling process will be escalated to root.

# Avoiding detection:
We have employed both syscall hooking as well as DKOM (direct kernel object manipulation) in an attempt to hide our rootkit.

### getdirentries():
* Running ktrace ls and then kdump revealed that the syscall, getdirentries() was being called to locate all the entries in each directory so we decided to hook this as part of the effort to hide our rootkit files.
* The syscall getdirentries() takes in a userspace buffer as one of its arguments. This buffer gets filled in with dirent structures which contain the name of the file/directory.
* Our hook simply calls the original syscall first and then loops over each dirent structure in the buffer. If the name matches with the file/directory we want to hide then we call bzero() to null the name buffer in the dirent structure, we set the size of the name buffer to 0 before setting the length of the entire record to 8.

### Manipulate list of linker files:
* In the kernel, there is a queue data structure that contains a list of linker files i.e kernel modules. When the rootkit is loaded in, it is added to this list.
* Our rootkit first acquires the lock kld_sx and then uses the queue macros TAILQ_FOREACH() to loop through the list of linker files. The function strncmp() is used to determine if the linker file matches our rootkit file and if it does then the macro TAILQ_REMOVE() is called to remove our rootkit from this list.
* The modules of the rootkit also need to be removed and the same process is repeated on the list of modules that is present in the kernel.

### open():
* To hide the rootkit from the FILE command, we decided to hook the open() syscall
* The syscall open() takes in a userspace buffer as one of its arguments, and the path of the file gets stored inside that buffer
* We check if the name of our rootkit is a substring of the supplied path, and if it’s true, then we throw an ENOENT error - which says “No such file or directory”, otherwise we call the open function normally with the given arguments

# Advanced Features:
### Backdoor:
Haven’t implemented yet

### Keylogger:
* To write a keylogger, we decided to hook a read() syscall that reads from STDIN.
* The hooked read() syscall will read from STDIN (file descriptor is 0) and store it into a char buffer. The keylogger then opens a file in the kernel address space called <insert name here> and the modes that are given to a file are append, create and write and gives the file a certain permission. The function to open a file is kern_openat() and this returns a file descriptor of the file opened.
* The keylogger then uses the file descriptor from kern_openat() to write to the buffer to the file and then the file is closed.  


### Restart persistence:
Our current thought for restart persistence is to take use of crontab which is a file which contains the schedule of cron entries to be run and at specified times. Then we can allow our rootkit to loaded in after restart by doing something like @reboot /path/to/job.
