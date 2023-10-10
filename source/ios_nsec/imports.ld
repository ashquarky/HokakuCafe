PROVIDE(printf = 0xe1088ef8);

PROVIDE(memcpy = 0xe108d394);
PROVIDE(memset = 0xe108d430);
PROVIDE(memcmp = 0xe108d2ac);
PROVIDE(strncpy = 0xe108deb8);
PROVIDE(snprintf = 0xe108de50);

PROVIDE(IOS_CreateThread = 0xe108e934);
PROVIDE(IOS_StartThread = 0xe108e96c);
PROVIDE(IOS_GetThreadPriority = 0xe108e984);
PROVIDE(IOS_CreateMessageQueue = 0xe108e994);
PROVIDE(IOS_DestroyMessageQueue = 0xe108e99c);
PROVIDE(IOS_ReceiveMessage = 0xe108e9b4);
PROVIDE(IOS_Alloc = 0xe108ea6c);
PROVIDE(IOS_AllocAligned = 0xe108ea74);
PROVIDE(IOS_Free = 0xe108ea7c);
PROVIDE(IOS_Open = 0xe108eacc);
PROVIDE(IOS_Close = 0xe108ead4);
PROVIDE(IOS_Ioctl = 0xe108eaf4);
PROVIDE(IOS_Ioctlv = 0xe108eafc);
PROVIDE(IOS_GetAbsTime64 = 0xe108ea1c); /* not sure on these two */
PROVIDE(IOS_GetAbsTimeCalendar = 0xe108ea24);
PROVIDE(IOS_CreateSemaphore = 0xe108ebec);
PROVIDE(IOS_WaitSemaphore = 0xe108ebf4);
PROVIDE(IOS_SignalSemaphore = 0xe108ebfc);
PROVIDE(IOS_DestroySemaphore = 0xe108ec04);

PROVIDE(SSL_do_handshake = 0xe101b8f4);
PROVIDE(SSL_read = 0xe101bb30);
PROVIDE(SSL_write = 0xe101ba50);
