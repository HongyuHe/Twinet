#!/bin/sh
# Start ovsdb-server and ovs-vswitchd, then hand over to the container command.
set -e
ip link set lo up 2>/dev/null || true

mkdir -p /var/run/openvswitch /var/log/openvswitch /etc/openvswitch

if [ ! -f /etc/openvswitch/conf.db ]; then
    ovsdb-tool create /etc/openvswitch/conf.db \
        /usr/share/openvswitch/vswitch.ovsschema
fi

ovsdb-server /etc/openvswitch/conf.db \
    --remote=punix:/var/run/openvswitch/db.sock \
    --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
    --pidfile=/var/run/openvswitch/ovsdb-server.pid \
    --log-file=/var/log/openvswitch/ovsdb-server.log \
    --detach

ovs-vsctl --no-wait init
ovs-vswitchd unix:/var/run/openvswitch/db.sock \
    --pidfile=/var/run/openvswitch/ovs-vswitchd.pid \
    --log-file=/var/log/openvswitch/ovs-vswitchd.log \
    --detach

exec "$@"
