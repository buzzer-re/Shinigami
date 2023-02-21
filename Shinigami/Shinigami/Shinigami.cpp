#include <iostream>
#include <windows.h>
#include <tchar.h>

#include "Injector.h"


int _tmain(int argc, TCHAR** argv)
{
    wchar_t* target = (wchar_t*) argv[1];
    Injector injector(target);

    injector.InjectSuspended(L".\\Ichigo.dll");
}
