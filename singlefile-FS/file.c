#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/timekeeping.h>
#include <linux/time.h>
#include <linux/buffer_head.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <linux/uio.h>
#include "singlefilefs.h"

spinlock_t lock;

ssize_t onefilefs_read(struct file * filp, char __user * buf, size_t len, loff_t * off) {

    loff_t offset;
    struct buffer_head *bh = NULL;
    struct inode * the_inode = filp->f_inode;
    uint64_t file_size = the_inode->i_size;
    int ret;
    int block_to_read;//index of the block to be read from device

    printk("%s: read operation called with len %ld - and offset %lld (the current file size is %lld)",MOD_NAME, len, *off, file_size);

    //this operation is not synchronized 
    //*off can be changed concurrently 
    //add synchronization if you need it for any reason
    spin_lock(&lock);
    //check that *off is within boundaries
    if (*off >= file_size){
        spin_unlock(&lock);
        return 0;}
    else if (*off + len > file_size){
        len = file_size - *off;}

    //determine the block level offset for the operation
 
    offset = *off % DEFAULT_BLOCK_SIZE; 
    //just read stuff in a single block - residuals will be managed at the applicatin level
    if (offset + len > DEFAULT_BLOCK_SIZE)
        len = DEFAULT_BLOCK_SIZE - offset;

    //compute the actual index of the the block to be read from device
    block_to_read = *off / DEFAULT_BLOCK_SIZE + 2; //the value 2 accounts for superblock and file-inode on device
    
    printk("%s: read operation must access block %d of the device",MOD_NAME, block_to_read);

    bh = (struct buffer_head *)sb_bread(filp->f_path.dentry->d_inode->i_sb, block_to_read);
    if(!bh){
        spin_unlock(&lock);
	    return -EIO;
    }
    ret = copy_to_user(buf,bh->b_data + offset, len);
    *off += (len - ret);
    brelse(bh);
    spin_unlock(&lock);
    return len - ret;

}


struct dentry *onefilefs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags) {

    struct onefilefs_inode *FS_specific_inode;
    struct super_block *sb = parent_inode->i_sb;
    struct buffer_head *bh = NULL;
    struct inode *the_inode = NULL;

    printk("%s: running the lookup inode-function for name %s",MOD_NAME,child_dentry->d_name.name);

    if(!strcmp(child_dentry->d_name.name, UNIQUE_FILE_NAME)){

	
	//get a locked inode from the cache 
        the_inode = iget_locked(sb, 1);
        if (!the_inode)
       		 return ERR_PTR(-ENOMEM);

	//already cached inode - simply return successfully
	if(!(the_inode->i_state & I_NEW)){
		return child_dentry;
	}


	
	//this work is done if the inode was not already cached
	inode_init_owner(current->cred->user_ns, the_inode, NULL, S_IFREG );
	the_inode->i_mode = S_IFREG | S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IXUSR | S_IXGRP | S_IXOTH;
        the_inode->i_fop = &onefilefs_file_operations;
	the_inode->i_op = &onefilefs_inode_ops;

	//just one link for this file
	set_nlink(the_inode,1);

	//now we retrieve the file size via the FS specific inode, putting it into the generic inode
    	bh = (struct buffer_head *)sb_bread(sb, SINGLEFILEFS_INODES_BLOCK_NUMBER );
    	if(!bh){
		iput(the_inode);
		return ERR_PTR(-EIO);
    	}
	FS_specific_inode = (struct onefilefs_inode*)bh->b_data;
	the_inode->i_size = FS_specific_inode->file_size;
        brelse(bh);

        d_add(child_dentry, the_inode);
	dget(child_dentry);

	//unlock the inode to make it usable 
    	unlock_new_inode(the_inode);

	return child_dentry;
    }

    return NULL;

}

//*from is the source of the data to be written
ssize_t onefilefs_write_iter(struct kiocb *iocb, struct iov_iter *from) {
    //pointer to the_file
    struct file *file;
    struct inode *filp_inode;
    loff_t blk_offset, size_file;
    int blk_to_write;
    //pointer to the head of the buffer
    struct buffer_head *bh;
    ssize_t ret;
    int start = 0;
    //total size of the payload
    int payload_size;
    char* buffer_data;

    //get pointer to file
    file = iocb->ki_filp;
    //size of data to write
    payload_size = iov_iter_count(from);

    if (IS_ERR(file)) {
        printk("%s: file not open correctly\n", MOD_NAME);
        return -EINVAL;
    }

    if (payload_size == 0) { // Check if there is data to write
        printk("%s: no data to write into log file\n", MOD_NAME);
        return 0;
    }

    //try to allocate a buffer of size payload_size
    buffer_data = kmalloc(payload_size, GFP_KERNEL);
    if (!buffer_data) {
        printk("%s: memory allocation failed\n", MOD_NAME);
        return -ENOMEM;
    }

    //copy data from from to buffer_data for the size of payload_size - if it does size != from payload_size something went wrong
    ret = copy_from_iter(buffer_data, payload_size, from);
    if (ret != payload_size) {
        kfree(buffer_data);
        return ret;
    }

    spin_lock(&lock);
    //pointer to the file inode
    filp_inode = file->f_inode;
    //current file size
    size_file = i_size_read(filp_inode); 

    //block offset calculation --> for example if size_file = 4100, blk_offset = 4 since 4100 % 4096 = 4
    blk_offset = size_file % DEFAULT_BLOCK_SIZE;
    //the number of the block to write to is calculated
    blk_to_write = size_file / DEFAULT_BLOCK_SIZE + 2; 

    while (payload_size > 0) { //as long as there is data in the payload
        bh = sb_bread(file->f_path.dentry->d_inode->i_sb, blk_to_write); //read block from FS to write to
        if (!bh) {
            spin_unlock(&lock);
            kfree(buffer_data);
            return -EIO;
        }

        //If payload > block size write as much as possible and move to the next block, otherwise write the data in the current block completely
        if (payload_size > DEFAULT_BLOCK_SIZE - blk_offset) {
            //bh->b_data + blk_offset is the pointer to the block + the offset (exact address of the block to write to)
            memcpy(bh->b_data + blk_offset, buffer_data + start, DEFAULT_BLOCK_SIZE - blk_offset);
            mark_buffer_dirty(bh);
            sync_dirty_buffer(bh);
            brelse(bh);
            
            payload_size -= (DEFAULT_BLOCK_SIZE - blk_offset);
            start += (DEFAULT_BLOCK_SIZE - blk_offset);
            size_file += (DEFAULT_BLOCK_SIZE - blk_offset);
            blk_offset = 0;
            blk_to_write++;
        } else {
            memcpy(bh->b_data + blk_offset, buffer_data + start, payload_size);
            mark_buffer_dirty(bh);
            sync_dirty_buffer(bh);
            brelse(bh);
            
            size_file += payload_size;
            payload_size = 0;
        }
    }

    //update the file size
    i_size_write(filp_inode, size_file);
    //dirty and modified inode sign
    mark_inode_dirty(filp_inode);
    spin_unlock(&lock);

    kfree(buffer_data);
    return ret;
}
//look up goes in the inode operations
const struct inode_operations onefilefs_inode_ops = {
    .lookup = onefilefs_lookup,
};

const struct file_operations onefilefs_file_operations = {
    .owner = THIS_MODULE,
    .read = onefilefs_read,
    .write_iter = onefilefs_write_iter
};
