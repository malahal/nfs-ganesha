#!/usr/bin/python

# You must initialize the gobject/dbus support for threading
# before doing anything.
import sys, gobject, dbus, dbus.glib
gobject.threads_init()
dbus.glib.init_threads()

# Create a session bus.
bus = dbus.SystemBus()

# Create an object that will proxy for a particular remote object.
admin = bus.get_object("org.ganesha.nfsd", "/org/ganesha/nfsd/admin")

# call method
method = admin.get_dbus_method('fsal_stats', 'org.ganesha.nfsd.admin')

(dumped, msg) = method()
if not dumped:
    print("Dumping stats failed: %s" % msg)
    sys.exit(1)
else:
    print("Dumped GPFS fsal stats to /tmp/fsal.stats file")
    print("Dumped NFSv3 OP stats to /tmp/nfsv3.stats file")
