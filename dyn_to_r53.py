import configparser, sys, getopt, json, os, copy, boto3, uuid, time
from pprint import pprint
from boto import route53
from dyn.tm.zones import Zone, get_all_zones, Node, get_all_secondary_zones
from dyn.tm.session import DynectSession
from dyn.tm.records import ARecord, AAAARecord, CNAMERecord, MXRecord, \
    PTRRecord, TXTRecord, SRVRecord, SPFRecord, ALIASRecord
from dyn.tm.errors import DynectCreateError

def login(setting_file):
    """
    Retrieve API parameters from settings.cfg and create sessions for both AWS Route 53 and Dynect.
    """
    global session
    config = configparser.ConfigParser()
    config.read(setting_file)
    company_name = config.get("DynSection", "company_name", raw=True)
    user_name = config.get("DynSection", "username", raw=True)
    password = config.get("DynSection", "password", raw=True)

    aws_access_key_id = config.get("AWSSection", "access_key", raw=True)
    aws_secret_access_key = config.get("AWSSection", "access_key_secret", raw=True)
    region = config.get("AWSSection", "region", raw=True)
    session = DynectSession(company_name, user_name, password)
    conn = route53.connect_to_region(region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    client = boto3.client('route53', region, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    return conn, client


def retrieve_zones_aws(conn, zone=None):
    """
    #Retrieve zone and record information from AWS and record it in a hash to be used to inject into Dyn.
    #:param conn - The AWS Connection created at login.
    #:param zone - The zone to be
    """
    zone_data = {}
    if zone is not None:
        aws_zones = conn.get_zone(zone)
        if aws_zones:
            zone_data[aws_zones.name[:-1]] = []
            rrset = aws_zones.get_records()
            for rec in rrset:
                zone_rec = {}
                zone_rec['name'] = rec.name[:-1]
                zone_rec['type'] = rec.type
                zone_rec['resource_recs'] = rec.resource_records
                if not zone_rec['resource_recs']:
                    zone_rec['resource_recs'] = [rec.alias_dns_name]
                    zone_rec['type'] = 'ALIAS'
                zone_rec['ttl'] = int(rec.ttl)
                zone_rec['zone_id'] = aws_zones.id
                zone_data[aws_zones.name[:-1]].append(zone_rec)
    else:
        aws_zones = conn.get_zones()
        for single_zone in aws_zones:
            zone_data[single_zone.name[:-1]] = single_zone.id
    return zone_data


def get_dyn_zones():
    return get_all_zones()


def retrieve_zones_dyn(zone=None):

    """
    # Retrieve zone and record information from AWS and record it in a hash to be used to inject into Dyn.
    # :param conn - The AWS Connection created at login.
    # :param zone - The zone to be
    """
    zone_data = {}
    if zone is not None:
        dyn_zones = [Zone(zone)]
    else:
        dyn_zones = get_all_zones()

    secondary_zones = get_all_secondary_zones()
    sec_zone_map = {}
    for sec_zone in secondary_zones:
        sec_zone_map[sec_zone.zone] = "Secondary"


    for i, single_zone in enumerate(dyn_zones):
        if single_zone.name in sec_zone_map:
            del dyn_zones[i]
        else:
            try:
                #node_records = Node(node.zone, node.fqdn).get_all_records()
                zone_records = single_zone.get_all_records()
                #print(zone_records)
                if zone_records and single_zone.name not in sec_zone_map:
                    all_recs = {}
                    for rec in zone_records:
                        zone_rec = {}
                        zone_rec['resource_recs'] = []
                        for rec_type in zone_records[rec]:
                            if rec_type.fqdn not in all_recs:
                                all_recs[rec_type.fqdn] = {}
                            if rec_type.rec_name not in all_recs[rec_type.fqdn]:
                                all_recs[rec_type.fqdn][rec_type.rec_name] = {}
                            all_recs[rec_type.fqdn][rec_type.rec_name]['type'] = rec_type.rec_name.upper()
                            all_recs[rec_type.fqdn][rec_type.rec_name]['name'] = rec_type.fqdn
                            type = rec_type.rec_name.upper()
                            if type == "PTR":
                                rrec = rec_type.ptrdname
                            elif type == "CNAME":
                                rrec = rec_type.cname
                            elif type == "TXT":
                                rrec = "\"" + rec_type.txtdata + "\""
                            elif type == "MX":
                                rrec = str(rec_type.preference) + " " + rec_type.exchange
                            elif type == "SRV":
                                srv_string = str(rec_type.priority) + " " + str(rec_type.weight) + " " + str(rec_type.port) + \
                                            " " + str(rec_type.target)
                                rrec = srv_string
                            elif type == "SPF":
                                rrec = "\"" + rec_type.txtdata + "\""
                            elif type == "ALIAS":
                                rrec = rec_type.alias
                            elif type == "SOA":
                                rrec = rec_type.rname
                            elif type == "NS":
                                rrec = rec_type.nsdname
                            else:
                                rrec = rec_type.address
                            if 'resource_recs' in all_recs[rec_type.fqdn][rec_type.rec_name]:
                                all_recs[rec_type.fqdn][rec_type.rec_name]['resource_recs'].append(rrec)
                            else:
                                all_recs[rec_type.fqdn][rec_type.rec_name]['resource_recs'] = [rrec]

                                all_recs[rec_type.fqdn][rec_type.rec_name]['ttl'] = rec_type._ttl
                    for node in all_recs:
                        for record_type in all_recs[node]:
                            if single_zone.name not in zone_data:
                                zone_data[single_zone.name] = [all_recs[node][record_type]]
                            else:
                                zone_data[single_zone.name].append(all_recs[node][record_type])
            except Exception as e:
                print(e)
    return zone_data


def retrieve_soa_dyn(zone=None):

    """
    # Retrieve zone and record information from AWS and record it in a hash to be used to inject into Dyn.
    # :param conn - The AWS Connection created at login.
    # :param zone - The zone to be
    """
    zone_soa = {}
    if zone is not None:
        dyn_zone = Zone(zone)
        zone_soa[dyn_zone.name[:-1]] = dyn_zone.serial
    else:
        dyn_zones = get_all_zones()
        for single_zone in dyn_zones:
            zone_soa[single_zone.name] = single_zone.serial
    return zone_soa


def copy_records(zone_data, zone_list_from, zone_list_to, override, conn):
    """
        Copy records that were retrieved from AWS into Dyn via API, remove records that exist only in Dyn and not AWS.
        :param override: If set to true records in Dyn that don't have a match in AWS will be removed
        :param zone_list: a list of zones to be updated based on the zone diff
        :param zone_data: The AWS Zone Data that was retrieved
        :param zone_email: E-mail address to be used when adding new zones to Dyn.
        """
    if zone_list_from is None:
        zone_list_from = list(zone_data.keys())

    for key in zone_list_from:
        zone_value = key
        existing_records = {}
        try:
            if zone_value not in zone_list_to:
                print("Zone_test")
                response = conn.create_hosted_zone(
                    Name=zone_value,
                    CallerReference=str(uuid.uuid4()),
                    HostedZoneConfig={
                        'Comment': 'Create new zone',
                        'PrivateZone': False
                    }
                )
                zone_id = response['HostedZone']['Id']
            else:
                zone_id = zone_list_to[zone_value][0]['zone_id']
        except Exception as e:
            print(e)
        if zone_value in zone_data:
            for rec in zone_data[zone_value]:
                rec_list = []
                if rec['type'] == "A":
                    for address in rec['resource_recs']:
                        rec_list.append(address)
                elif rec['type'] == "AAAA":
                    for address in rec['resource_recs']:
                        rec_list.append(address)
                elif rec['type'] == "CNAME":
                    for address in rec['resource_recs']:
                        rec_list.append(address)
                elif rec['type'] == "MX":
                    for address in rec['resource_recs']:
                        mail = address.split()
                        rec_list.append(mail[0] + " " + mail[1])
                elif rec['type'] == "PTR":
                    for address in rec['resource_recs']:
                        rec_list.append(address)
                elif rec['type'] == "TXT":
                    for txtdata in rec['resource_recs']:
                        rec_list.append(txtdata )
                elif rec['type'] == "SRV":
                    for srvdata in rec['resource_recs']:
                        rec_list.append(srvdata)
                elif rec['type'] == "SPF":
                    for txtdata in rec['resource_recs']:
                        rec_list.append(txtdata)
                res_recs = []
                for rrec in rec_list:
                    res_recs.append({'Value':rrec})
                if res_recs:
                    result = conn.change_resource_record_sets(HostedZoneId=zone_id,
                                                              ChangeBatch={
                                                                  'Changes': [
                                                                      {
                                                                          'Action': 'UPSERT',
                                                                          'ResourceRecordSet': {
                                                                              'Name': rec['name'],
                                                                              'Type': rec['type'],
                                                                              'TTL': int(rec['ttl']),
                                                                              'ResourceRecords': res_recs
                                                                          }
                                                                      }
                                                                  ]}
                                                              )
                #print(result)
                time.sleep(.2)
            if override:
                for rec_info, rec_id in existing_records.items():
                    cleanup_records(rec_info, rec_id, zone_value)
            #new_zone.publish()


def create(create_records, zone_email, override, delete_records, client):
    """
        Create records that were retrieved from AWS into Dyn via API, remove records that exist only in Dyn and not AWS.
        After checking against a cached
        :param override: If set to true records in Dyn that don't have a match in AWS will be removed
        :param delete_records: Records from the diff that need to be deleted for parity.
        :param create_records: Records after the diff that need to be created for sync
        :param zone_email: E-mail address to be used when adding new zones to Dyn.
        """
    for zone_name in create_records:
        try:
            zone = Zone(zone_name, zone_email)
            zone.publish()
        except:
            zone = Zone(zone_name)
            zone_records = zone.get_all_records()
        for rec in create_records[zone_name]:
            if rec['type'] == "A":
                for address in rec['resource_recs']:
                    try:
                        record = ARecord(zone_name, rec['name'], address=address, ttl=rec['ttl'])
                        print("SUCCESS: Record " + rec['name'] + " at: " + address + " created")
                    except DynectCreateError:
                        print("EXISTS " + rec['name'] + " at: " + address + " Already exists")
                    except:
                        print("FAILURE: Record " + rec['name'] + " at: " + address + " was not created")
                        sys.exc_info()
            elif rec['type'] == "AAAA":
                for address in rec['resource_recs']:
                    try:
                        record = AAAARecord(zone_name, rec['name'], address=address, ttl=rec['ttl'])
                        print("SUCCESS: Record " + rec['name'] + " at: " + address + " created")
                    except DynectCreateError:
                        print("EXISTS " + rec['name'] + " at: " + address + " Already exists")
                    except:
                        print("FAILURE: Record " + rec['name'] + " at: " + address + " was not created")
                        sys.exc_info()
            elif rec['type'] == "CNAME":
                for address in rec['resource_recs']:
                    try:
                        record = CNAMERecord(zone_name, rec['name'], cname=address, ttl=rec['ttl'])
                        print("SUCCESS: Record " + rec['name'] + " at: " + address + " created")
                    except DynectCreateError:
                        record = CNAMERecord(zone_name, rec['name'], create=False)
                        record.delete()
                        zone.publish()
                        record = CNAMERecord(zone_name, rec['name'], cname=address, ttl=rec['ttl'])
                        print("UPDATED " + rec['name'] + " at: " + address + " was updated")
                    except:
                        print("FAILURE: Record " + rec['name'] + " at: " + address + " was not created")
                        sys.exc_info()
            elif rec['type'] == "ALIAS":
                for address in rec['resource_recs']:
                    try:
                        record = ALIASRecord(zone_name, rec['name'], alias=address, ttl=rec['ttl'])
                        print("SUCCESS: Record " + rec['name'] + " at: " + address + " created")
                    except DynectCreateError:
                        record = ALIASRecord(zone_name, rec['name'], create=False)
                        record.delete()
                        zone.publish()
                        record = ALIASRecord(zone_name, rec['name'], alias=address, ttl=rec['ttl'])
                        print("UPDATED " + rec['name'] + " at: " + address + " was updated")
                    except:
                       print("FAILURE: Record " + rec['name'] + " at: " + address + " was not created")
                       sys.exc_info()
            elif rec['type'] == "MX":
                for address in rec['resource_recs']:
                    mail = address.split()
                    try:
                        record = MXRecord(zone_name, rec['name'], preference=mail[0], exchange=mail[1], ttl=rec['ttl'])
                        print("SUCCESS: Record " + rec['name'] + " at: " + address + " created")
                    except DynectCreateError:
                        print("EXISTS " + rec['name'] + " at: " + address + " Already exists")
                    except:
                        print("FAILURE: Record " + rec['name'] + " at: " + address + " was not created")
                        sys.exc_info()
            elif rec['type'] == "PTR":
                for address in rec['resource_recs']:
                    try:
                        record = PTRRecord(zone_name, rec['name'], ptrdname=address, ttl=rec['ttl'])
                        print("SUCCESS: Record " + rec['name'] + " at: " + address + " created")
                    except DynectCreateError:
                        print("EXISTS " + rec['name'] + " at: " + address + " Already exists")
                    except:
                        print("FAILURE: Record " + rec['name'] + " at: " + address + " was not created")
                        sys.exc_info()
            elif rec['type'] == "TXT":
                for txtdata in rec['resource_recs']:
                    try:
                        record = TXTRecord(zone_name, rec['name'], txtdata=txtdata, ttl=rec['ttl'])
                        print("SUCCESS: Record " + rec['name'] + " with data: " + txtdata + " created")
                    except DynectCreateError:
                        print("EXISTS " + rec['name'] + " with data: " + txtdata + " Already exists")
                    except:
                        print("FAILURE: Record " + rec['name'] + " at: " + address + " was not created")
                        sys.exc_info()
            elif rec['type'] == "SRV":
                for srvdata in rec['resource_recs']:
                    srv_list = srvdata.split()
                    try:
                        record = SRVRecord(zone_name, rec['name'], port=srv_list[2], priority=srv_list[0], target=srv_list[3], weight=srv_list[1], ttl=rec['ttl'])
                        print("SUCCESS: Record " + rec['name'] + " with data: " + srvdata + " created")
                    except DynectCreateError:
                        print("EXISTS " + rec['name'] + " with data: " + srvdata + " Already exists")
                    except:
                        print("FAILURE: Record " + rec['name'] + " at: " + address + " was not created")
                        sys.exc_info()
            elif rec['type'] == "SPF":
                for txtdata in rec['resource_recs']:
                    try:
                        record = SPFRecord(zone_name, rec['name'], txtdata=txtdata, ttl=rec['ttl'])
                        print("SUCCESS: Record " + rec['name'] + " with data: " + txtdata + " created")
                    except DynectCreateError:
                        print("EXISTS " + rec['name'] + " with data: " + txtdata + " Already exists")
                    except:
                        print("FAILURE: Record " + rec['name'] + " at: " + address + " was not created")
                        sys.exc_info()
        if override:
            for record in delete_records[zone_name]:
                override_records(record, zone_name)
        zone.publish()


def override_records(record, zone):
    """
    Records to be removed to create parity between AWS and the Dyn, removal of outdated records.
    :param record: The record to be removed from Dyn
    :param zone: Zone the record exists in

    """
    record_type = record['type']
    record_fqdn = record['name']
    if record_type == "A":
        rec = ARecord(zone, record_fqdn, address=record['resource_recs'][0], create=False)
        rec.delete()
    elif record_type == "AAAA":
        rec = AAAARecord(zone, record_fqdn, address=record['resource_recs'][0], create=False)
        rec.delete()
    elif record_type == "SPF":
        rec = SPFRecord(zone, record_fqdn, txtdata=record['resource_recs'][0], create=False)
        rec.delete()
    elif record_type == "SRV":
        srv_list = record['resource_recs'][0].split()
        rec = SRVRecord(zone, record_fqdn, port=srv_list[2], priority=srv_list[0], target=srv_list[3], weight=srv_list[1], create=False)
        rec.delete()
    elif record_type == "TXT":
        rec = TXTRecord(zone, record_fqdn, txtdata=record['resource_recs'][0], create=False)
        rec.delete()
    elif record_type == "PTR":
        rec = PTRRecord(zone, record_fqdn, ptrdname=record['resource_recs'][0], create=False)
        rec.delete()
    elif record_type == "MX":
        mail = record['resource_recs'][0].split()
        rec = MXRecord(zone, record_fqdn, preference=mail[0], exchange=mail[1], create=False)
        rec.delete()
    elif record_type == "ALIAS":
        rec = ALIASRecord(zone, record_fqdn, alias=record['resource_recs'][0], create=False)
        rec.delete()
    elif record_type == "CNAME":
        rec = CNAMERecord(zone, record_fqdn, cname=record['resource_recs'][0], create=False)
        rec.delete()
    print("REMOVED: Record " + record_fqdn + " was removed during sync")


def cleanup_records(records, zone_id, conn):
    """
    Cleanup records will remove non-matched records from Dyn using record ID to force parity between AWS and Dyn.
    :param record: Record information to be removed from Dyn
    :param record_id: Record ID from Dyn to be removed.
    :param zone: Zone of the record of interest.
    """
    for zone in records:
        for rec in records[zone]:
            if rec['type'] != 'NS' and rec['type'] != 'SOA':
                res_records = []
                for rrec in rec['resource_recs']:
                    res_records = [{'Value':rrec}]
                    try:
                        change_batch = {
                                'Changes': [
                                    {
                                        'Action': 'DELETE',
                                        'ResourceRecordSet': {
                                            'Name': rec['name'],
                                            'Type': rec['type'],
                                            'TTL': int(rec['ttl']),
                                            'ResourceRecords': res_records
                                        }
                                    }
                                ]}
                        print(change_batch)
                        print(zone_id)
                        result = conn.change_resource_record_sets(HostedZoneId=zone_id,
                                                                      ChangeBatch=change_batch
                                                                      )
                        print(result)
                    except Exception as e:
                        print(e)
                    print("REMOVED: Record " + rec['name'] + " was removed during sync")


def cache_to_file(write_data, zone, serials=False):
    """
    Record zone records to file for check in future runs
    :param zone_data: JSON of the zone or zones that have been synchronized.
    :param zone: Zone name for storage of data on single zone runs, None if all zones.
    """
    if serials:
        with open('serials.json', 'w') as outfile:
            json.dump(write_data, outfile)
    elif zone is None:
        with open('zones.json', 'w') as outfile:
            json.dump(write_data, outfile)
    else:
        with open(zone+'_zones.json', 'w') as outfile:
            json.dump(write_data, outfile)


def read_cache(zone=None, serials=False):
    """
    Read cached serial information from file to compare against new zone check.
    :param zone: The zone to be synchronized, if set to None all zones will be retrieved.
    """
    if serials:
        if os.path.isfile('serials.json'):
            with open('serials.json') as infile:
                return json.load(infile)
        else:
            return None
    elif zone is None:
        if os.path.isfile('zones.json'):
            with open('zones.json') as infile:
                return json.load(infile)
        else:
            return None
    else:
        if os.path.isfile(zone + '_zones.json'):
            with open(zone + '_zones.json') as infile:
                return json.load(infile)
        else:
            return None


def compare_soa_recs(serial_data, cache_serial_data):
    """
        Read cached serial information from file to compare against new zone check.
        :param zone: The zone to be synchronized, if set to None all zones will be retrieved.
        """
    changed_zones = []
    for zone in serial_data:
        if cache_serial_data:
            if serial_data[zone] != cache_serial_data[zone]:
                changed_zones.append(zone)
        else:
            changed_zones.append(zone)

    return changed_zones


def changes_exist(zone_data, cache_data, zone=None):
    """
    Verify if changes exist between the last successful run and the newly retrieved record information.
    :param zone_data: The JSON of zones and records retrieved from AWS to check against cached data
    :param cache_data: The JSON of zones and records retrieved from the local cache.
    :param zone: The zone of interest for this run, if None all zones will be checked.
    """
    change_list = []
    if zone is None:
        if cache_data is None:
            return True, None
        elif zone_data == cache_data:
            return False, None
        else:
            for zone in zone_data:
                try:
                    if zone_data[zone] == cache_data[zone]:
                        print("No Changes in: " + zone)
                    else:
                        change_list.append(zone)
                except:
                    change_list.append(zone)
            print(change_list)
            return True, change_list
    else:
        if cache_data is None:
            return True, None
        elif zone_data[zone] == cache_data[zone]:
            return False, None
        else:
            return True, None


def diff_changes(zone_data, cache_data, change_list):
    """
    Compare newly retrieved data from AWS to the existing cached JSON of records from the last successful run
    :param zone_data: New zones and records retrieved from AWS in JSON
    :param cache_data: Existing cached zones and records retrieved from cache file in JSON
    :param change_list: List of zones that have changes as reported by changes_exist() call.
    """
    create_records = {}
    delete_records = {}
    for zone in change_list:
        if zone in zone_data:
            new_zone = zone_data[zone]
            cache_zone = cache_data[zone]
            zone_match = list()
            cache_match = list()

            for key, rec in enumerate(new_zone):
                for cache_key, cache_rec in enumerate(cache_zone):
                    if 'zone_id' in cache_rec:
                        del cache_rec['zone_id']
                    print(rec)
                    print(cache_rec)
                    if rec == cache_rec:
                        zone_match.append(key)
                        cache_match.append(cache_key)
                    elif rec['type'] == "ALIAS":
                        if rec['name'] == cache_rec['name']:
                            cache_match.append(cache_key)
                    elif rec['type'] == "CNAME":
                        if rec['name'] == cache_rec['name']:
                            cache_match.append(cache_key)

            zone_match.sort(reverse=True)
            cache_match.sort(reverse=True)
            for i in zone_match:
                del new_zone[i]
            for k in cache_match:
                del cache_zone[k]
            create_records[zone] = new_zone
            delete_records[zone] = cache_zone
    return create_records, delete_records


def synchronize(command, override, force, zone=None):
    """
    Function to kick off synchronization from Route53 to Dyn
    :param command - can be either test or run, test will return a json of changes in Route53 and a delta between the cached version.
    :param zone - zone is the specific zone to be migrated, can be set to None for all zones.
    :param override - override and remove any records in Dyn that don't have a match in Route53
    :param force -
    """
    if command == "test":
        if zone == "all":
            zone = None
        conn = login()
        zone_data = retrieve_zones_dyn(zone)
        pprint(zone_data)
    elif command == "run":
        if zone == "":
            print("Please specify a zone -z <zone> or use -z all to synchronize all zones")
        else:
            if zone == "all":
                zone = None
            conn = login()
            config = configparser.ConfigParser()
            config.read("settings.cfg")
            zone_email = config.get("DynSection", "zone_email", raw=True)
            zone_data = retrieve_zones_dyn(zone)
            original_zone = copy.deepcopy(zone_data)
            cache_data = read_cache(zone)
            changes, zone_list = changes_exist(original_zone, cache_data, zone)
            if force is True:
                copy_records(original_zone, zone_email, zone_list, override)
                cache_to_file(zone_data, zone)
            else:
                if changes is False:
                    print("No Changes")
                else:
                    print("Changes exist")
                    if zone_list is None:
                        copy_records(original_zone, zone_email, zone_list, override)
                        cache_to_file(zone_data, zone)
                    else:
                        create_records, delete_records = diff_changes(original_zone, cache_data, zone_list)
                        create(create_records, zone_email, override, delete_records)
                        cache_to_file(zone_data, zone)


def main(argv):
    try:
        opts, args = getopt.getopt(argv,"htrofz:",["test","run", "zone", "override", "force"])
    except getopt.GetoptError:
        print('migrate.py --test/--run --zone <zone to sync>')
        sys.exit(2)
    zone = ""
    command = ""
    override = False
    force = False
    for opt, arg in opts:
        if opt == '-h':
            print('migrate.py --test/--run --zone <zone to sync>')
            sys.exit()
        elif opt in ("-t", "--test"):
            command = "test"
            login("settings.cfg")
            zone_data = retrieve_zones_dyn()
            pprint(zone_data)
        elif opt in ("-r", "--run"):
            command = "run"
        elif opt in ("-z", "--zone"):
            zone = arg
        elif opt in ("-o", "--override"):
            override = True
        elif opt in ("-f", "--force"):
            force = True

    if command == "test":
        if zone == "all":
            zone = None
        login("settings.cfg")
        zone_data = retrieve_zones_dyn(zone)
        cache_data = read_cache(zone)
        original_zone = copy.deepcopy(zone_data)
        changes, zone_list = changes_exist(original_zone, cache_data, zone)
        if zone_list is None:
            pprint(original_zone)
        else:
            create_records, delete_records = diff_changes(original_zone, cache_data, zone_list)
            print("================= RECORDS TO BE CREATED =================")
            pprint(create_records)
            print("================= RECORDS TO BE DELETED =================")
            pprint(delete_records)
    elif command == "run":
        if zone == "":
            print("Please specify a zone -z <zone> or use -z all to synchronize all zones")
        else:
            if zone == "all":
                zone = None
            conn = login("settings.cfg")
            config = configparser.ConfigParser()
            config.read("settings.cfg")
            zone_data_dyn = retrieve_zones_dyn(zone)
            zone_data_aws = retrieve_zones_aws(conn, zone)
            original_zone = copy.deepcopy(zone_data_dyn)
            #cache_data = read_cache(zone)
            changes, zone_list = changes_exist(zone_data_dyn, zone_data_aws, zone)
            if force is True:
                copy_records(original_zone, zone_list, override, conn)
                #cache_to_file(zone_data, zone)
            else:
                if changes is False:
                    print("No Changes")
                else:
                    print("Changes exist")
                    if zone_list is None:
                        copy_records(original_zone, zone_list, override, conn)
                        #cache_to_file(zone_data, zone)
                    else:
                        print("else")
                        #create_records, delete_records = diff_changes(original_zone, cache_data, zone_list)

                        #create(zone_data, delete_records, conn)
                        #create(create_records, zone_email, override, delete_records)
                        #cache_to_file(zone_data, zone)


if __name__ == "__main__":
    main(sys.argv[1:])
