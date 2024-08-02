#include "generic.h"

void move_files(void)
{
    mkdir("/var/spawnjb/");
    cp("/private/var/mobile/Media/jb","/var/spawnjb/");
    cp("/private/var/mobile/Media/jb.plist","/var/spawnjb/");
    cp("/private/var/mobile/Media/launchd.conf","/var/spawnjb/");
    cp("/private/var/mobile/Media/amfi.dylib","/var/spawnjb/");
}

int
main()
{
    move_files();

    return 0;
}
