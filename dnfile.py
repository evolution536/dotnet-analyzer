import dnfile
import hashlib
import sys

pe = dnfile.dnPE(sys.argv[1])

# access the directory entry raw structure values
pe.net.struct

# access the metadata raw structure values
pe.net.metadata.struct

# access the streams
for s in pe.net.metadata.streams_list:
    if isinstance(s, dnfile.stream.MetaDataTables):
        # how many Metadata tables are defined in the binary?
        num_of_tables = len(s.tables_list)

# the last Metadata tables stream can also be accessed by a shortcut
num_of_tables = len(pe.net.mdtables.tables_list)

# create a set to hold the hashes of all resources
res_hash = set()
# access the resources
for r in pe.net.resources:
    # if resource data is a simple byte stream
    if isinstance(r.data, bytes):
        # hash it and add the hash to the set
        res_hash.add(hashlib.sha256(r.data).hexdigest())
    # if resource data is a ResourceSet, a dotnet-specific datatype
    elif isinstance(r.data, dnfile.resource.ResourceSet):
        # if there are no entries
        if not r.data.entries:
            # skip it
            continue
        # for each entry in the ResourceSet
        for entry in r.data.entries:
            # if it has data
            if entry.data:
                # hash it and add the hash to the set
                res_hash.add(hashlib.sha256(entry.data).hexdigest())
