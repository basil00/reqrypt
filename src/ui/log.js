/*
 * log.js
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

if (request == null)
{
    alert("unable to create request object");
}

function getLog()
{
    url = "log-entry.txt";
    request.open("GET", url, true);
    request.onreadystatechange = updateLog;
    request.send(null);
    setTimeout("getLog()", 500);
}

function updateLog()
{
    if (request.readyState == 4 && request.status == 200)
    {
        log_div = document.getElementById("log");
        if (log_div)
        {
            log_div.innerHTML = request.responseText;
            window.scrollBy(0, 9999999);
        }
    }
}

