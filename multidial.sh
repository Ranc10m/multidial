#!/bin/bash

# Path to programs
ECHO=$(which echo)

# Defaults
VTH='vth'
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
    local ipv4=''
    ipv4=$(get_ip "$ifname" --ipv4)
    [ -z "$ipv4" ] && return 1
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
    local ppp_ifname
    if [ "$2" = "-ipv6" ]; then
        enable_ipv6=1
    fi
    if [ -z "$ifname" ]; then
        $ECHO "$ME: You must specify a interface" >&2
        exit 1
    fi
    if [[ -f /var/run/$linkname.pid || -f /etc/ppp/$linkname.pid ]]; then
        ppp_ifname=get_pppoe_ifname "$ifname"
        $ECHO "$ME: There already seems to be a PPPoE connection up $linkname($ppp_ifname)" >&2
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
    printf "Trying to create connection for %s " "$ifname"
    while true; do
        ppp_ifname=$(get_pppoe_ifname "$ifname")
        if [ -n "$ppp_ifname" ]; then
            local ipv4=''
            local ipv6=''
            ipv4=$(get_ip "$ppp_ifname" --ipv4)
            if [ -n "$ipv4" ]; then
                [ "$enable_ipv6" = "1" ] && build_isatap_tunnel "$ppp_ifname"
                ipv6=$(get_ip "$ppp_ifname" --ipv6)
                printf " Connected! ipv4:%s ipv6:%s\\n" "$ipv4" "$ipv6"
                return 0
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
    local ifname=$1
    local enable_ipv6=0
    if [ "$2" = "--ipv6" ]; then
        enable_ipv6=1
    fi
    if [ -z "$ifname" ]; then
        $ECHO "$ME: You must specify a interface"
        exit 1
    fi
    if [ -n "$(get_ip "$ifname" --ipv4)" ]; then
        $ECHO "$ME: There already seems to be a connection up $linkname" >&2
        exit 1
    fi
    ip link show "$ifname" >/dev/null 2>&1 || create_virtual_interface "$ifname"
    ip link set "$ifname" up
    dhclient -nw "$ifname"
    local TIME=0
    printf "Trying to create connection for %s " "$ifname"
    while true; do
        local ipv4=''
        local ipv6=''
        ipv4=$(get_ip "$ifname" --ipv4)
        if [ -n "$ipv4" ]; then
            [ "$enable_ipv6" = "1" ] && build_isatap_tunnel "$ifname"
            ipv6=$(get_ip "$ppp_ifname" --ipv6)
            printf " Connected! ipv4:%s ipv6:%s\\n" "$ipv4" "$ipv6"
            return 0
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

static_dial() {
    local ifname=$1
    local ipv4=$2
    local netmask=$3
    local enable_ipv6=0
    if [ "$4" = "--ipv6" ]; then
        enable_ipv6=1
    fi
    if [ -z "$ifname" ]; then
        $ECHO "$ME: You must specify a interface"
        exit 1
    fi
    if [ -n "$(get_ip "$ifname" --ipv4)" ]; then
        $ECHO "$ME: There already seems to be a connection up $linkname" >&2
        exit 1
    fi
    printf "Trying to create connection for %s " "$ifname"
    ip link show "$ifname" >/dev/null 2>&1 || create_virtual_interface "$ifname"
    ip link set "$ifname" up
    if ip addr add "$ipv4"/"$netmask" dev "$ifname" >/dev/null 2>&1; then
        [ "$enable_ipv6" = "1" ] && build_isatap_tunnel "$ifname"
        ipv6=$(get_ip "$ppp_ifname" --ipv6)
        printf " Connected! ipv4:%s ipv6:%s\\n" "$ipv4" "$ipv6"
        return 0
    fi
    remove_virtual_interface "$ifname"
    $ECHO " Failed!" >&2
    exit 1
}

#ifname ip gateway
configure_routing_table() {
    echo
}

get_next_vth_id() {
    local cur=1
    while true; do
        ip link show "$VTH""$cur" >/dev/null 2>&1 || break
        cur=$((cur + 1))
    done
    $ECHO "$cur"
}

bulk_dial() {
    local optname
    local vth_id
    local pppoe_num
    local dhcp_num
    local static_num
    while getopts ":p:d:s" optname; do
        case "$optname" in
        "p")
            pppoe_num=$OPTARG
            ;;
        "d")
            dhcp_num=$OPTARG
            ;;
        "s")
            static_num=$OPTARG
            ;;
        "?")
            echo "Unknown option $OPTARG"
            exit 1
            ;;
        ":")
            echo "No argument value for option $OPTARG"
            exit 1
            ;;
        "*")
            # Should not occur
            echo "Unknown error while processing options"
            exit 1
            ;;
        esac
    done

    while [ "$pppoe_num" -gt 0 ]; do
        vth_id=$(get_next_vth_id)
        pppoe_dial "$vth_id"
        pppoe_num=$((pppoe_num - 1))
    done

    while [ "$dhcp_num" -gt 0 ]; do
        vth_id=$(get_next_vth_id)
        pppoe_dial "$vth_id"
        dhcp_num=$((dhcp_num - 1))
    done

    echo "$static_num"
}

case "$1" in
-i)
    ifname=$2
    bulk_dial -p 10
    ;;
-r)
    ifname=$2
    dial_clean_all "$ifname"
    ;;
*)
    $ECHO "Usage: $ME {-i|-r} [IFNAME]"
    ;;
esac
