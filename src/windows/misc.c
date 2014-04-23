/*
 * misc.c
 * (C) 2014, all rights reserved,
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _WIN32_WINNT 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>

#include "cfg.h"
#include "log.h"
#include "misc.h"
#include "options.h"
#include "thread.h"

#define WM_SYSTRAY_ICON     (WM_USER + 1)

/*
 * The main window.
 */
static HWND window = NULL;

/*
 * Main entry point.
 */
int MAIN(int argc, char **argv);

/*
 * Window's callback.
 */
LRESULT CALLBACK WndProc(HWND window, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch(msg)
    {
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        case WM_COMMAND:
            if (LOWORD(wparam) == WM_DESTROY)
            {
                PostQuitMessage(0);
            }
            break;
        case WM_SYSTRAY_ICON:
            if (LOWORD(lparam) == WM_RBUTTONDOWN)
            {
                HMENU menu = CreatePopupMenu();
                MENUITEMINFO item;
                memset(&item, 0x0, sizeof(MENUITEMINFO));
                item.cbSize = sizeof(MENUITEMINFO);
                item.fMask = MIIM_STATE | MIIM_ID | MIIM_TYPE;
                item.wID = WM_DESTROY;
                item.fType = MFT_STRING;
                item.fState = MFS_ENABLED;
                char label[] = PROGRAM_NAME_LONG " Exit...";
                item.dwTypeData = label;
                item.cch = sizeof(label)-1;

                InsertMenuItem(menu, 0, false, &item);

                POINT point;
                GetCursorPos(&point);
                SetForegroundWindow(window);
                TrackPopupMenu(menu,
                    TPM_LEFTALIGN | TPM_LEFTBUTTON | TPM_BOTTOMALIGN,
                    point.x, point.y, 0, window, NULL);
                break;
            }
            // Fall through:
        default:
            return DefWindowProc(window, msg, wparam, lparam);
    }
    return 0;
}

/*
 * Window handler thread.
 */
static void *window_handler_thread(void *inst_ptr)
{
    HINSTANCE inst = (HINSTANCE)inst_ptr;

    // Create a dummy window so we get a taskbar button:
    WNDCLASSEX class;
    memset(&class, 0x0, sizeof(class));
    class.cbSize        = sizeof(WNDCLASSEX);
    class.lpfnWndProc   = WndProc;
    class.hInstance     = inst;
    class.lpszClassName = PROGRAM_NAME_LONG;

    if (!RegisterClassEx(&class))
    {
        MessageBox(NULL, "Unable to register window class", NULL, MB_OK);
        return NULL;
    }

    window = CreateWindowEx(WS_EX_CLIENTEDGE, PROGRAM_NAME_LONG,
        PROGRAM_NAME_LONG, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
        CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, inst, NULL);
   
    if (window == NULL)
    {
        MessageBox(NULL, "Unable to create window", NULL, MB_OK);
        return NULL;
    }

    NOTIFYICONDATA nid;
    memset(&nid, 0x0, sizeof(NOTIFYICONDATA));
    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd   = window;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    HICON icon = LoadIcon(inst, "icon");
    if (icon == NULL)
    {
        MessageBox(NULL, "Unable to load program icon", NULL, MB_OK);
        return NULL;
    }
    nid.hIcon = icon;
    _tcscpy(nid.szTip, _T(PROGRAM_NAME_LONG));
    nid.uCallbackMessage = WM_SYSTRAY_ICON;
    Shell_NotifyIcon(NIM_ADD, &nid);
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    Shell_NotifyIcon(NIM_DELETE, &nid);

    exit(EXIT_SUCCESS);
}

/*
 * Windows entry point.
 */
int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev_inst, PSTR cmdline,
    int cmdshow)
{
    // Attach to the parent console if it exists.
    if (AttachConsole(ATTACH_PARENT_PROCESS))
    {
        freopen("conout$", "w", stdout);
        freopen("conout$", "w", stderr);
        putchar('\n');
    }

    // Window thread:
    thread_t thread;
    if (thread_create(&thread, window_handler_thread, (void *)inst) != 0)
    {
        return EXIT_FAILURE;
    }

    // Translate command-line arguments:
    LPWSTR *largv;
    int argc;

    largv = CommandLineToArgvW(GetCommandLineW(), &argc);
    char *argv[argc+1];
    for (int i = 0; i < argc; i++)
    {
        size_t len = wcslen(largv[i]);
        argv[i] = malloc(len*sizeof(char)+1);
        if (argv[i] == NULL)
        {
            return EXIT_FAILURE;
        }
        wcstombs(argv[i], largv[i], len+1);
    }
    argv[argc] = NULL;
    return MAIN(argc, argv);
}

/*
 * Platform specific initialisation.
 */
void platform_init(void)
{
}

/*
 * Initialise a buffer with random data
 */
void random_ext_init(uint8_t *ptr, size_t size)
{
    // This implementation uses RtlGenRandom (a.k.a. SystemFunction036).
    // However this function is not exposed in MinGW.  Nor is rand_s.  Instead
    // we resort to loading the function dynamically.

    static bool init = false;
    static BOOLEAN (APIENTRY *func)(void *, ULONG);

    if (!init)
    {
        init = true;
        const char *libname = "advapi32.dll";
        HMODULE lib = LoadLibrary(libname);
        if (lib == NULL)
        {
            error("unable to load library \"%s\"", libname);
        }

        const char *funcname = "SystemFunction036";
        func = (BOOLEAN (APIENTRY *)(void *, ULONG))
            GetProcAddress(lib, funcname);
        // Never close lib, we need it for as run as the program is running
        
        if (func == NULL)
        {
            error("unable to find function %s in library \"%s\"",
                funcname, libname);
        }
    }

    if (!func((PVOID)ptr, (ULONG)size))
    {
        error("unable to initialize " SIZE_T_FMT " bytes of random data",
            size);
    }
}

/*
 * Change to home directory
 */
void chdir_home(void)
{
    // NOP in Windows -- we are always in the home directory.
}

/*
 * Launch the UI.
 */
void launch_ui(uint16_t port)
{
    const char url_fmt[] = "http://localhost:%u/";
    char url[sizeof(url_fmt) - 2 + 5];      // - "%u" + 5 port digits
    snprintf(url, sizeof(url), url_fmt, port);
    ShellExecute(NULL, "open", url, NULL, NULL, SW_SHOWDEFAULT);
}

/*
 * Gets the current time in microseconds.
 */
uint64_t gettime(void)
{
    FILETIME file_time;
    GetSystemTimeAsFileTime(&file_time);

    LARGE_INTEGER lint;
    lint.LowPart  = file_time.dwLowDateTime;
    lint.HighPart = file_time.dwHighDateTime;

    return lint.QuadPart / 10;
}

/*
 * Sleep for the given number of microseconds.
 */
void sleeptime(uint64_t us)
{
    Sleep(us / MILLISECONDS);
}

/*
 * Quit this application.
 */
void quit(int status)
{
    if (window != NULL)
    {
        PostMessage(window, WM_DESTROY, 0, 0);
        sleeptime(1*SECONDS);
    }
    exit(status);
}

