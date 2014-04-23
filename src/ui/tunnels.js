/*
 * tunnels.js
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

var request = null;
try
{
    request = new XMLHttpRequest();
}
catch (trymicrosoft)
{
    try
    {
        request = new ActiveXObject("Msxml2.XMLHTTP");
    }
    catch (othermicrosoft)
    {
        try
        {
            request = new ActiveXObject("Microsoft.XMLHTTP");
        }
        catch (failed)
        {
            request = null;
        }
    }
}

if (!request)
{
    alert("unable to create request object");
}

function getTunnels()
{
    url = "tunnels-all.html";
    request.open("GET", url, true);
    request.onreadystatechange = updateAllTunnels;
    request.send(null);
    setTimeout("getTunnels2()", 50);
}

function getTunnels2()
{
    url = "tunnels-active.html";
    request.open("GET", url, true);
    request.onreadystatechange = updateActiveTunnels;
    request.send(null);
    setTimeout("getTunnels()", 2000);
}

function updateAllTunnels()
{
    if (request.readyState == 4 && request.status == 200)
    {
        tunnels_all_select = document.getElementById("tunnels_all_select");
        if (tunnels_all_select)
        {
            tunnels_all_select.innerHTML = request.responseText;
            reselectTunnel();
        }
    }
}

function updateActiveTunnels()
{
    if (request.readyState == 4 && request.status == 200)
    {
        tunnels_select = document.getElementById("tunnels_select");
        if (tunnels_select)
        {
            tunnels_select.innerHTML = request.responseText;
            reselectTunnel();
        }
    }
}

function selectActiveTunnel()
{
    tunnels_select = document.getElementById("tunnels_select");
    tunnels_all_select = document.getElementById("tunnels_all_select");
    tunnel = document.getElementById("tunnel");
    if (tunnels_select && tunnels_all_select && tunnel)
    {
        for (i = 0; i < tunnels_all_select.length; i++)
        {
            if (tunnels_all_select[i].selected)
            {
                tunnels_all_select[i].selected = false;
                break;
            }
        }
        for (i = 0; i < tunnels_select.length; i++)
        {
            if (tunnels_select[i].selected)
            {
                tunnel.value = tunnels_select[i].value;
                return;
            }
        }
    }
}

function selectAllTunnel()
{
    tunnels_select = document.getElementById("tunnels_select");
    tunnels_all_select = document.getElementById("tunnels_all_select");
    tunnel = document.getElementById("tunnel");
    if (tunnels_select && tunnels_all_select && tunnel)
    {
        for (i = 0; i < tunnels_select.length; i++)
        {
            if (tunnels_select[i].selected)
            {
                tunnels_select[i].selected = false;
                break;
            }
        }
        for (i = 0; i < tunnels_all_select.length; i++)
        {
            if (tunnels_all_select[i].selected)
            {
                tunnel.value = tunnels_all_select[i].value;
                reselectTunnel();
                return;
            }
        }
    }
}

function reselectTunnel()
{
    tunnel = document.getElementById("tunnel");
    if (!tunnel || tunnel.value == "")
    {
        return;
    }
    tunnels_select = document.getElementById("tunnels_select");
    tunnels_all_select = document.getElementById("tunnels_all_select");
    if (tunnels_select && tunnels_all_select)
    {
        for (i = 0; i < tunnels_select.length; i++)
        {
            if (tunnels_select[i].value == tunnel.value)
            {
                tunnels_select[i].selected = true;
                return;
            }
        }
        for (i = 0; i < tunnels_all_select.length; i++)
        {
            if (tunnels_all_select[i].value == tunnel.value)
            {
                tunnels_all_select[i].selected = true;
                return;
            }
        }
    }
}

function addTunnel()
{
    document.state.ADD_URL.value = document.tunnels.tunnel.value;
    doSubmit();
}

function delTunnel()
{
    document.state.DEL_URL.value = document.tunnels.tunnel.value;
    doSubmit();
}

