/*
 * install.cpp
 * (C) 2010, all rights reserved,
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

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <netcfgn.h>
#include <netcfgx.h>
#include <setupapi.h>
#include <devguid.h>
#include <objbase.h>

#include "../cfg.h"

/*
 * This is a tool for installing/uninstalling the NDIS intermediate driver.
 */

#define WRITE_LOCK_TIMEOUT      100

static void error(const char *message, int winerr)
{
    LPTSTR err_str = NULL;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        0, winerr, 0, (LPTSTR)&err_str, 0, 0);
    fprintf(stderr, "error: %s: %s\n", message, err_str);
    LocalFree(err_str);
}

static void __cdecl cleanup_on_exit(void)
{
    CoUninitialize();
}

int __cdecl main(int argc, char **argv)
{
    bool ok(false);
    bool install;
    if (argc == 2)
    {
        if (strcmp(argv[1], "install") == 0)
        {
            printf("Installing %s driver...\n", PACKAGE_NAME);
            ok = true;
            install = true;
        }
        else if (strcmp(argv[1], "uninstall") == 0)
        {
            printf("Uninstalling %s driver...\n", PACKAGE_NAME);
            ok = true;
            install = false;
        }
    }

    if (!ok)
    {
        fprintf(stderr, "usage: %s install\n", argv[0]);
        fprintf(stderr, "       %s uninstall\n", argv[0]);
        return EXIT_FAILURE;
    }

    HRESULT result = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (result != S_OK)
    {
        error("unable to initialise the COM library", HRESULT_CODE(result));
        return EXIT_FAILURE;
    }
    atexit(cleanup_on_exit);

    INetCfg *netcfg;
    result = CoCreateInstance(CLSID_CNetCfg, NULL, CLSCTX_INPROC_SERVER,
        IID_INetCfg, (void **)&netcfg);
    if (result != S_OK)
    {
        error("unable to create uninitialised object of the NetCfg class",
            HRESULT_CODE(result));
        return EXIT_FAILURE;
    }

    INetCfgLock *netcfg_lock;
    result = netcfg->QueryInterface(IID_INetCfgLock, (LPVOID *)&netcfg_lock);
    if (result != S_OK)
    {
        error("unable to get the write lock for the NetCfg object",
            HRESULT_CODE(result));
        return EXIT_FAILURE;
    }

    result = netcfg_lock->AcquireWriteLock(WRITE_LOCK_TIMEOUT,
        DRIVER_INSTALLER_NAME, NULL);
    if (result != S_OK)
    {
        error("unable to aquire write lock for the NetCfg object",
            HRESULT_CODE(result));
        return EXIT_FAILURE;
    }

    result = netcfg->Initialize(NULL);
    if (result != S_OK)
    {
        error("unable to initialise the NetCfg object", HRESULT_CODE(result));
        return EXIT_FAILURE;
    }
    netcfg->AddRef();

    OBO_TOKEN obo_token;
    memset(&obo_token, 0x0, sizeof(obo_token));
    obo_token.Type = OBO_USER;

    if (install)
    {
        if (!SetupCopyOEMInf(DRIVER_INF_PATH, DRIVER_PATH, SPOST_PATH, 0,
                NULL, 0, NULL, NULL))
        {
            error("unable to copy driver.inf file", GetLastError());
            return EXIT_FAILURE;
        }
        if (!SetupCopyOEMInf(DRIVER_M_INF_PATH, DRIVER_PATH, SPOST_PATH, 0,
                NULL, 0, NULL, NULL))
        {
            error("unable to copy driver_m.inf file", GetLastError());
            return EXIT_FAILURE;
        }

        INetCfgClassSetup *netcfg_setup;
        result = netcfg->QueryNetCfgClass(&GUID_DEVCLASS_NETSERVICE,
            IID_INetCfgClassSetup, (void **)&netcfg_setup);
        if (result != S_OK)
        {
            error("unable to get NetCfg interface to 'Service' class of "
                "network components", HRESULT_CODE(result));
            return EXIT_FAILURE;
        }

        INetCfgComponent *netcfg_component;
        result = netcfg_setup->Install(DRIVER_ID, &obo_token, 0, 0, NULL,
            NULL, &netcfg_component);
        if (result != S_OK)
        {
            error("unable to install network component", HRESULT_CODE(result));
            return EXIT_FAILURE;
        }
        netcfg_setup->Release();
        netcfg_component->Release();

        result = netcfg->Apply();
        if (result != S_OK)
        {
            error("unable to apply the installation of the network component",
                HRESULT_CODE(result));
            return EXIT_FAILURE;
        }

        printf("Success: %s driver installed...\n", PACKAGE_NAME);
    }
    else
    {
        INetCfgComponent *netcfg_component;
        result = netcfg->FindComponent(DRIVER_ID, &netcfg_component);
        if (result != S_OK)
        {
            error("unable to find the network component",
                HRESULT_CODE(result));
            return EXIT_FAILURE;
        }

        GUID guid;
        result = netcfg_component->GetClassGuid(&guid);
        if (result != S_OK)
        {
            error("unable to get the class GUID for network component",
                HRESULT_CODE(result));
            return EXIT_FAILURE;
        }

        INetCfgClass *netcfg_class;
        result = netcfg->QueryNetCfgClass(&guid, IID_INetCfgClass,
            (void **)&netcfg_class);
        if (result != S_OK)
        {
            error("unable to get the network configuration interface for "
                "network component", HRESULT_CODE(result));
            return EXIT_FAILURE;
        }

        INetCfgClassSetup *netcfg_setup;
        result = netcfg_class->QueryInterface(IID_INetCfgClassSetup,
            (void **)&netcfg_setup);
        if (result != S_OK)
        {
            error("unable to get NetCfg interface to 'Service' class of "
                "network components", HRESULT_CODE(result));
            return EXIT_FAILURE;
        }

        result = netcfg_setup->DeInstall(netcfg_component, &obo_token,
            NULL);
        if (result != S_OK)
        {
            error("unable to uninstall network component",
                HRESULT_CODE(result));
            return EXIT_FAILURE;
        }

        result = netcfg->Apply();
        if (result != S_OK)
        {
            error("unable to apply the uninstallation of the network "
                "component", HRESULT_CODE(result));
            return EXIT_FAILURE;
        }

        printf("Success: %s driver uninstalled...\n", PACKAGE_NAME);
    }

    // From this point on we return EXIT_SUCCESS, since the driver should now
    // be installed/uninstalled.
    result = netcfg_lock->ReleaseWriteLock();
    if (result != S_OK)
    {
        error("unable to release write lock for NetCfg object",
            HRESULT_CODE(result));
        return EXIT_SUCCESS;
    }
    netcfg->Release();

    result = netcfg->Uninitialize();
    if (result != S_OK)
    {
        error("unable to uninitialise the NetCfg object",
            HRESULT_CODE(result));
        return EXIT_SUCCESS;
    }

    return EXIT_SUCCESS;
}

