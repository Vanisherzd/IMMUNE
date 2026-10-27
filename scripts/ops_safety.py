"""Argument validation for container diagnostics and safe ordering for rollback."""
import ipaddress
import re
import shlex
import urllib.parse


READ_PROGRAMS = {"cat", "ls", "ps", "df", "du", "tail", "head", "grep", "id"}
CURL_FLAGS = {"--silent", "--show-error", "--fail", "--head", "--include", "--verbose", "--compressed"}
CURL_VALUES = {"--max-time", "--connect-timeout", "--request", "--url"}
CURL_SHORT_VALUES = {"-m": "--max-time", "-X": "--request"}
STACK_HOSTS = {"localhost", "edge-victim", "edge-victim-app"}
IP_OBJECTS = {"addr", "address", "a", "route", "r", "link", "l", "neigh", "n"}
SS_OPTION_LETTERS = set("ltunpasie46")
GETENT_DATABASES = {"hosts", "ahosts", "ahostsv4", "ahostsv6", "services"}
LOOKUP_PROGRAMS = {"nslookup", "dig", "host"}


def diagnostic_argv(command):
    """Accept diagnostic programs, never a shell, config loader, or child launcher."""
    if not isinstance(command, str) or any(c in command for c in ("\0", "\n", "\r", "$(", "`")):
        raise ValueError("cmd must be one diagnostic command without shell substitutions or newlines")
    try:
        argv = shlex.split(command)
    except ValueError as error:
        raise ValueError("cmd has unmatched quotes") from error
    if not argv or any(a in {";", "&&", "||", "|", "&", ">", ">>", "<", "2>&1"} for a in argv):
        raise ValueError("shell operators are not supported")
    program = argv[0]
    if program == "nginx":
        if argv not in (["nginx", "-t"], ["nginx", "-T"]):
            raise ValueError("nginx diagnostics only accept nginx -t or nginx -T")
    elif program == "env":
        if len(argv) != 1:
            raise ValueError("env may print the environment but may not launch another command")
    elif program == "curl":
        return _curl_argv(argv[1:])
    elif program == "ip":
        return _ip_argv(argv[1:])
    elif program == "ss":
        return _ss_argv(argv[1:])
    elif program == "getent":
        if len(argv) != 3 or argv[1] not in GETENT_DATABASES or argv[2].startswith("-"):
            raise ValueError("getent only accepts hosts/ahosts/ahostsv4/ahostsv6/services and one name")
    elif program in LOOKUP_PROGRAMS:
        if len(argv) != 2 or argv[1].startswith(("-", "+", "@")):
            raise ValueError(f"{program} only accepts one name without options or an alternate server")
    elif program not in READ_PROGRAMS:
        raise ValueError("only nginx -t/-T, cat, ls, ps, curl, df, du, tail, head, grep, id, env, ip, ss, getent, "
                         "nslookup, dig, and host are allowed")
    if program == "tail" and any(a.startswith("--follow") or
                                  (a.startswith("-") and not a.startswith("--") and any(c in a[1:] for c in "fF"))
                                  for a in argv[1:]):
        raise ValueError("tail must finish; follow mode is not allowed")
    return argv


def _ip_argv(arguments):
    valid = (len(arguments) == 1 and arguments[0] in IP_OBJECTS) or (
        len(arguments) == 2 and arguments[0] in IP_OBJECTS and arguments[1] in {"show", "list"}
    ) or (
        len(arguments) == 3 and arguments[0] in IP_OBJECTS and arguments[1] in {"show", "list"}
        and re.fullmatch(r"[A-Za-z0-9@.:-]+", arguments[2]) is not None
    )
    if not valid:
        raise ValueError("ip diagnostics only accept ip addr/address/a, route/r, link/l, or neigh/n, optionally "
                         "followed by show/list and one device name")
    return ["ip", *arguments]


def _ss_argv(arguments):
    if any(len(argument) < 2 or not argument.startswith("-") or argument.startswith("--") or
           any(letter not in SS_OPTION_LETTERS for letter in argument[1:]) for argument in arguments):
        raise ValueError("ss options are limited to -l -t -u -n -p -a -s -i -e -4 -6, optionally combined; "
                         "filters and kill are not allowed")
    return ["ss", *arguments]


def _curl_argv(arguments):
    urls = []
    options = []
    index = 0
    positional = False
    while index < len(arguments):
        arg = arguments[index]
        index += 1
        if arg == "--" and not positional:
            positional = True
            continue
        if not positional and arg.startswith("-"):
            key, equal, value = arg.partition("=")
            key = CURL_SHORT_VALUES.get(key, key)
            if key in CURL_VALUES:
                if not equal:
                    if index >= len(arguments):
                        raise ValueError(f"{key} requires a value")
                    value = arguments[index]
                    index += 1
                if key == "--request":
                    if value not in {"GET", "HEAD"}:
                        raise ValueError("curl only supports GET or HEAD")
                    options.extend([key, value])
                elif key == "--url":
                    urls.append(value)
                else:
                    try:
                        seconds = float(value)
                    except ValueError as error:
                        raise ValueError("curl timeouts must be numbers") from error
                    if not 0 < seconds <= 10:
                        raise ValueError("curl timeouts must be greater than zero and at most 10 seconds")
                    options.extend([key, value])
            elif arg in CURL_FLAGS or (arg.startswith("-") and not arg.startswith("--") and
                                        len(arg) > 1 and all(c in "sSfIiv" for c in arg[1:])):
                options.append(arg)
            else:
                raise ValueError(f"curl option {arg!r} is not a read-only diagnostic option")
        else:
            urls.append(arg)
    if len(urls) != 1:
        raise ValueError("curl needs exactly one http(s) URL on this stack or the private network")
    _check_url(urls[0])
    # Disable curlrc, proxies, URL globbing and redirects; none may expand the checked request.
    return ["curl", "--disable", "--globoff", "--noproxy", "*", "--proto", "=http,https",
            "--max-redirs", "0", "--max-time", "5", *options, "--url", urls[0]]


def _check_url(url):
    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ValueError("curl URL is malformed") from error
    if parsed.scheme not in {"http", "https"} or not host or parsed.username is not None or parsed.password is not None:
        raise ValueError("curl needs an http(s) URL without embedded credentials")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("curl URL has an invalid port")
    if host in STACK_HOSTS:
        return
    try:
        address = ipaddress.ip_address(host)
    except ValueError as error:
        raise ValueError("curl host must be localhost, a stack container, or a private IP literal") from error
    if address.is_link_local or address.is_multicast or address.is_unspecified or not (address.is_private or address.is_loopback):
        raise ValueError("curl target must be loopback or private, excluding link-local and multicast")


def restore_config_file(current, source, previous):
    """Read the rollback source before rotating its potentially identical backup path.

    Keep the current file's inode: nginx mounts this individual file read-only, so
    replacing the inode would leave an existing container reading the old file.
    """
    restored = source.read_text()
    replaced = current.read_text()
    previous.write_text(replaced)
    current.write_text(restored)
