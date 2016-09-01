#include <stdio.h>
#include <mntent.h>
#include <string.h>
#include <sys/vfs.h>
static const unsigned long long G = 1024*1024*1024ull;
static const unsigned long long M = 1024*1024;
static const unsigned long long K = 1024;
static char str[20];
char* kscale(unsigned long b, unsigned long bs)
{
    unsigned long long size = b * (unsigned long long)bs;
    if (size > G)
    {
        sprintf(str, "%0.2fG", size/(G*1.0));
        return str;
    }
    else if (size > M)
    {
        sprintf(str, "%0.2fM", size/(1.0*M));
        return str;
    }
    else if (size > K)
    {
        sprintf(str, "%0.2fK", size/(1.0*K));
        return str;
    }
    else
    {
        sprintf(str, "%0.2fB", size*1.0);
        return str;
    }
}

int get_disk_inf(void)
{
    FILE* mount_table;
    struct mntent *mount_entry;
    struct statfs s;
    unsigned long blocks_used;
    unsigned blocks_percent_used;
    const char *disp_units_hdr = NULL;
    mount_table = NULL;

    mount_table = setmntent("/etc/mtab", "r");
    if (!mount_table)
    {
        fprintf(stderr, "set mount entry error/n");
        return -1;
    }
    disp_units_hdr = "     Size";
    printf("Filesystem           %-15sUsed Available %s Mounted on\n",
            disp_units_hdr, "Use%");
    while (1) {
        const char *device;
        const char *mount_point;
        if (mount_table) {
            mount_entry = getmntent(mount_table);
            if (!mount_entry) {
                endmntent(mount_table);
                break;
            }
        }
        else
            continue;
        device = mount_entry->mnt_fsname;
        mount_point = mount_entry->mnt_dir;
        //fprintf(stderr, "mount info: device=%s mountpoint=%s/n", device, mount_point);
        if (statfs(mount_point, &s) != 0)
        {
            fprintf(stderr, "statfs failed!/n");
            continue;
        }
        if ((s.f_blocks > 0) || !mount_table )
        {
            blocks_used = s.f_blocks - s.f_bfree;
            blocks_percent_used = 0;
            if (blocks_used + s.f_bavail)
            {
                blocks_percent_used = (blocks_used * 100ULL
                        + (blocks_used + s.f_bavail)/2
                        ) / (blocks_used + s.f_bavail);
            }
            /* GNU coreutils 6.10 skips certain mounts, try to be compatible.  */
            if (strcmp(device, "rootfs") == 0)
                continue;
            if (printf("\n%-20s" + 1, device) > 20)
                   printf("\n%-20s", "");
            char size[20];//Size
            char used[20];//Used
            char avail[20];//Available
            strcpy(size, kscale(s.f_blocks, s.f_bsize));
            strcpy(used, kscale(s.f_blocks - s.f_bfree, s.f_bsize));
            strcpy(avail, kscale(s.f_bavail, s.f_bsize));
            printf(" %9s %9s %9s %3u%% %s\n",
                    size,
                    used,
                    avail,
                    blocks_percent_used, mount_point);
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    get_disk_inf();

    return 0;
}
