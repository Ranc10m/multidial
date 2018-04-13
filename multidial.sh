#!/bin/bash

# Path to programs
ECHO=$(which echo)

# Defaults
ETH='eth0'
USER='scu@edu'
PASSWORD=''
CONNECT_POLL=1
CONNECT_TIMEOUT=10
IPV6_PREFIX="2001:250:2003:2010:200:5efe"
REMOTE_ROUTER="202.115.39.98"

ME=$(basename "$0")
# Must be root
if [ "$(/usr/bin/id -u)" != 0 ]; then
    $ECHO "$ME: You must be root to run this script" >&2
    exit 1
fi

get_ip() {
    local ifname=$1
    local family=''
    [ "$2" = "--ipv4" ] && family='-4'
    [ "$2" = "--ipv6" ] && family='-6'
    local addresses=''
    addresses=$(ip $family addr show "$ifname" 2>/dev/null |
        grep -o -E 'inet6? *[^ /]*' | awk '{print $2}')
    $ECHO "$addresses"
}

build_isatap_tunnel() {
    local ifname=$1
    local isatap_ifname=isa-"$ifname"
    ping -c2 -W 2 "$REMOTE_ROUTER" | grep ttl >/dev/null || return 1
    local ipv4=''
    ipv4=$(get_ip "$ifname")
    [ -z "$ipv4" ] && return
    ip tunnel add "$isatap_ifname" mode sit remote "$REMOTE_ROUTER" local "$ipv4"
    ip link set dev "$isatap_ifname" up
    ip -6 addr add "$IPV6_PREFIX":"$ipv4"/64 dev "$isatap_ifname"
}

destroy_isatap_tunnel() {
    local ifname=$1
    local isatap_ifname=isa-"$ifname"
    if ip link show | grep "$isatap_ifname" >/dev/null; then
        ip link set "$isatap_ifname" down
        ip tunnel del "$isatap_ifname"
    fi
}

get_pppoe_ifname() {
    local ifname=$1
    local linkname=ppp-$ifname
    local ppp_ifname=''
    [ -f /var/run/"$linkname".pid ] && ppp_ifname=$(sed -n '2p' </var/run/"$linkname".pid)
    [ -f /etc/ppp/"$linkname".pid ] && ppp_ifname=$(sed -n '2p' </etc/ppp/"$linkname".pid)
    $ECHO "$ppp_ifname"
}

pppoe_stop() {
    local ifname=$1
    local linkname=ppp-$ifname
    local ppp_ifname=''
    local pppd_id=''
    ppp_ifname=$(get_pppoe_ifname "$ifname")
    [ -n "$ppp_ifname" ] && destroy_isatap_tunnel "$ppp_ifname"
    [ -f /var/run/"$linkname".pid ] && pppd_id=$(sed -n '1p' </var/run/"$linkname".pid)
    [ -f /etc/ppp/"$linkname".pid ] && pppd_id=$(sed -n '1p' </etc/ppp/"$linkname".pid)
    [ -n "$pppd_id" ] && kill "$pppd_id" >/dev/null 2>&1
}

create_virtual_interface() {
    local ifname=$1
    if ! ip link add link $ETH name "$ifname" type macvlan >/dev/null 2>&1; then
        $ECHO "Cannot create virtual interface $ifname" >&2
        exit 1
    fi
}

remove_virtual_interface() {
    local ifname=$1
    ip link show "$ifname" >/dev/null 2>&1 || return
    if ip link show "$ifname" | grep "$ifname"@$ETH >/dev/null; then
        ip link set "$ifname" down
        ip link del "$ifname"
    fi
}

dial_clean_all() {
    local ifname=$1
    pppoe_stop "$ifname"
    destroy_isatap_tunnel "$ifname"
    remove_virtual_interface "$ifname"
}

pppoe_dial() {
    local ifname=$1
    local linkname=ppp-$ifname
    local enable_ipv6=0
    if [ "$2" = "--ipv6" ]; then
        enable_ipv6=1
    fi
    if [ -z "$ifname" ]; then
        $ECHO "$ME: You must specify a interface"
        exit 1
    fi
    if [[ -f /var/run/$linkname.pid || -f /etc/ppp/$linkname.pid ]]; then
        $ECHO "$ME: There already seems to be a PPPoE connection up $linkname" >&2
        exit 1
    fi
    # interface has not exist yet
    ip link show "$ifname" >/dev/null 2>&1 || create_virtual_interface "$ifname"
    ip link set "$ifname" up
    if ! pppd plugin rp-pppoe.so "$ifname" linkname "$ifname" \
        persist hide-password noauth user "$USER" password "$PASSWORD" >/dev/null 2>&1; then
        remove_virtual_interface "$ifname"
        $ECHO "Cannot create connection for $ifname" >&2
        exit 1
    fi
    local TIME=0
    printf "%s" "Trying to create connection for $ifname "
    while true; do
        local ppp_ifname
        ppp_ifname=$(get_pppoe_ifname "$ifname")
        if [ -n "$ppp_ifname" ]; then
            local ipv4=''
            ipv4=$(get_ip "$ppp_ifname" --ipv4)
            if [ -n "$ipv4" ]; then
                [ "$enable_ipv6" = "1" ] && build_isatap_tunnel "$ppp_ifname"
                $ECHO " Connected!"
                exit 0
            fi
        fi
        printf .
        sleep $CONNECT_POLL
        TIME=$((TIME + CONNECT_POLL))
        if [ $TIME -gt $CONNECT_TIMEOUT ]; then
            break
        fi
    done
    dial_clean_all "$ifname"
    $ECHO " Failed!" >&2
    exit 1
}

dhcp_dial() {
    $ECHO hello
}

static_dial() {
    $ECHO hello
}

dial_up() {
    $ECHO hello
}

dial_down() {
    $ECHO hello
}

dial_status() {
    $ECHO hello
}

case "$1" in
-i)
    ifname=$2
    pppoe_dial "$ifname" --ipv6
    ;;
-r)
    ifname=$2
    dial_clean_all "$ifname"
    ;;
*)
    $ECHO "Usage: $ME {-u|-d} [IFNAME]"
    ;;
esac
