/*
 * motd.js
 * (C) 2018, all rights reserved,
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

var request2 = null;
try
{
    request2 = new XMLHttpRequest();
}
catch (trymicrosoft)
{
    try
    {
        request2 = new ActiveXObject("Msxml2.XMLHTTP");
    }
    catch (othermicrosoft)
    {
        try
        {
            request2 = new ActiveXObject("Microsoft.XMLHTTP");
        }
        catch (failed)
        {
            request2 = null;
        }
    }
}

if (request2 == null)
{
    alert("unable to create request2 object");
}

function getMOTD()
{
    if (document.state.CHECK_UPDATES.value == "true")
    {
        url = "https://reqrypt.org/motd-01.txt";
        request2.open("GET", url, true);
        request2.onreadystatechange = updateMOTD;
        request2.send(null);
    }
}

function updateMOTD()
{
    if (request2.readyState == 4 && request2.status == 200)
    {
        motd_div = document.getElementById("motd");
        if (motd_div)
        {
            motd_div.innerHTML = request2.responseText;
        }
    }
}

