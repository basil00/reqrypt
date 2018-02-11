/*
 * script.js
 * (C) 2017, all rights reserved,
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

function doLoad()
{
    copyFromState();
    activateTab();
}

function activateTab()
{
    if (document.log)
    {
        var log_tab = document.getElementById("log_tab");
        log_tab.className += " active";
        return;
    }

    if (document.options)
    {
        var options_tab = document.getElementById("options_tab");
        options_tab.className += " active";
        return;
    }

    if (document.tunnels)
    {
        var tunnels_tab = document.getElementById("tunnels_tab");
        tunnels_tab.className += " active";
        return;
    }

    if (document.help)
    {
        var help_tab = document.getElementById("help_tab");
        help_tab.className += " active";
        return;
    }

    if (document.license)
    {
        var license_tab = document.getElementById("license_tab");
        license_tab.className += " active";
        return;
    }
}

function doSubmit()
{
    copyToState();
    document.state.save.value = true;
    document.state.submit();
}

function copyToState()
{
    if (document.options)
    {
        document.state.ENABLED.value = copyFromRadio(document.options.enabled);
        switch (document.options.http_mode.value)
        {
            case "all":
                document.state.HIDE_TCP.value = "true";
                document.state.HIDE_TCP_SYN.value = "set";
                document.state.HIDE_TCP_ACK.value = "set";
                document.state.HIDE_TCP_PSH.value = "set";
                document.state.HIDE_TCP_FIN.value = "set";
                document.state.HIDE_TCP_RST.value = "set";
                document.state.HIDE_TCP_DATA.value = "false";
                document.state.TUNNEL.value = "true";
                document.state.SPLIT_MODE.value = "none";
                break;
            case "data": case "url": case "urlpart":
                document.state.HIDE_TCP.value = "true";
                document.state.HIDE_TCP_SYN.value = "*";
                document.state.HIDE_TCP_ACK.value = "set";
                document.state.HIDE_TCP_PSH.value = "set";
                document.state.HIDE_TCP_FIN.value = "*";
                document.state.HIDE_TCP_RST.value = "*";
                document.state.HIDE_TCP_DATA.value = "true";
                document.state.TUNNEL.value = "true";
                switch (document.options.http_mode.value)
                {
                    case "data":
                        document.state.SPLIT_MODE.value = "none";
                        break;
                    case "url":
                        document.state.SPLIT_MODE.value = "full";
                        break;
                    case "urlpart":
                        document.state.SPLIT_MODE.value = "partial";
                        break;
                }
                break;
            case "split":
                document.state.HIDE_TCP.value = "true";
                document.state.HIDE_TCP_SYN.value = "*";
                document.state.HIDE_TCP_ACK.value = "set";
                document.state.HIDE_TCP_PSH.value = "set";
                document.state.HIDE_TCP_FIN.value = "*";
                document.state.HIDE_TCP_RST.value = "*";
                document.state.HIDE_TCP_DATA.value = "true";
                document.state.TUNNEL.value = "false";
                document.state.SPLIT_MODE.value = "partial";
                break;
            case "none":
                document.state.HIDE_TCP.value = "false";
                document.state.HIDE_TCP_SYN.value = "*";
                document.state.HIDE_TCP_ACK.value = "*";
                document.state.HIDE_TCP_PSH.value = "*";
                document.state.HIDE_TCP_FIN.value = "*";
                document.state.HIDE_TCP_RST.value = "*";
                document.state.HIDE_TCP_DATA.value = "false";
                document.state.TUNNEL.value = "true";
                document.state.SPLIT_MODE.value = "none";
                break;
            default:
                alert("invalid HTTP hide mode: \"" +
                      document.options.http_mode.value + "\"");
                return;
        }
        document.state.LAUNCH_UI.value =
            copyFromRadio(document.options.launch_ui);
        switch (document.options.nat_mode.value)
        {
            case "never":
                document.state.GHOST_MODE.value = "none";
                break;
            case "automatic":
                document.state.GHOST_MODE.value = "nat";
                break;
            case "always":
                document.state.GHOST_MODE.value = "always";
                break;
            default:
                alert("invalid NAT traversal mode: \"" +
                    document.options.nat_mode.value + "\"");
                return;
        }
        switch (document.options.nat_method.value)
        {
            case "ttl":
                document.state.GHOST_SET_TTL.value = "true";
                document.state.GHOST_CHECK.value = "true";
                break;
            case "checksum":
                document.state.GHOST_SET_TTL.value = "false";
                document.state.GHOST_CHECK.value = "false";
                break;
            case "combination":
                document.state.GHOST_SET_TTL.value = "false";
                document.state.GHOST_CHECK.value = "false";
                break;
            default:
                alert("invalid NAT method: \"" +
                    document.options.nat_method.value + "\"");
                return;
        }
        document.state.FRAG_MODE.value =
            copyFromSelect(document.options.frag_mode);
        document.state.HIDE_UDP.value =
            copyFromRadio(document.options.dns_mode);
        document.state.GHOST_TTL.value = copyFromSelect(document.options.ttl);
        document.state.MULTI_ROUTE.value =
            copyFromRadio(document.options.multi_route);
    }

    if (document.log)
    {
        document.state.LOG_LEVEL.value =
            copyFromSelect(document.log.log_level);
    }
}

function copyFromState()
{
    if (document.options)
    {
        copyToRadio(document.state.ENABLED.value, document.options.enabled);
        // Note: we pick the HTTP hide mode that most closely matches the
        // given filter parameters:
        if (document.state.HIDE_TCP.value == "false")
        {
            document.options.http_mode.value = "none";
        }
        else if (document.state.HIDE_TCP_DATA.value == "true")
        {
            if (document.state.TUNNEL.value == "false")
            {
                document.options.http_mode.value = "split";
            }
            else
            {
                switch (document.state.SPLIT_MODE.value)
                {
                    case "none":
                        document.options.http_mode.value = "data";
                        break;
                    case "full":
                        document.options.http_mode.value = "url";
                        break;
                    default:
                        document.options.http_mode.value = "urlpart";
                        break;
                }
            }
        }
        else
        {
            document.options.http_mode.value = "all";
        }
        switch (document.state.GHOST_MODE.value)
        {
            case "none":
                document.options.nat_mode.value = "never";
                break;
            case "always":
                document.options.nat_mode.value = "always";
                break;
            default:
                document.options.nat_mode.value = "automatic";
                break;
        }
        if (document.state.GHOST_CHECK.value == "true")
        {
            document.options.nat_method.value = "ttl";
        }
        else if (document.state.GHOST_SET_TTL.value == "true")
        {
            document.options.nat_method.value = "combination";
        }
        else
        {
            document.options.nat_method.value = "checksum";
        }
        copyToRadio(document.state.LAUNCH_UI.value, document.options.launch_ui);
        copyToSelect(document.state.FRAG_MODE.value,
            document.options.frag_mode);
        copyToRadio(document.state.HIDE_UDP.value, document.options.dns_mode);
        copyToSelect(document.state.GHOST_TTL.value, document.options.ttl);
        copyToRadio(document.state.MULTI_ROUTE.value,
            document.options.multi_route)
    }

    if (document.log)
    {
        copyToSelect(document.state.LOG_LEVEL.value, document.log.log_level);
    }
}

function copyToRadio(value, radio)
{
    for (i = 0; i < radio.length; i++)
    {
        if (value == radio[i].value)
        { 
            radio[i].checked = true;
            break;
        }
    }
}

function copyFromRadio(radio)
{
    for (i = 0; i < radio.length; i++)
    {
        if (radio[i].checked)
        {
            return radio[i].value;
        }
    }
    return "";
}

function copyToSelect(value, select)
{
    for (i = 0; i < select.length; i++)
    {
        if (value == select[i].value)
        {
            select[i].selected = true;
            break;
        }
    }
}

function copyFromSelect(select)
{
    for (i = 0; i < select.length; i++)
    {
        if (select[i].selected)
        {
            return select[i].value;
        }
    }
    return "";
}

function exit()
{
    if (confirm("Exit $PROGRAM?"))
    {
        window.location = "exit";
    }
}

