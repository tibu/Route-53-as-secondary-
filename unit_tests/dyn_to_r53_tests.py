import unittest, dyn_to_r53, boto3, copy


class TestDynToR53Sync(unittest.TestCase):

    def test_get_zones(self):

        conn, client = dyn_to_r53.login("../settings.cfg")
        serial_hash = dyn_to_r53.retrieve_soa_dyn()

        cache_serial_data = dyn_to_r53.read_cache(None, True)

        change_list = dyn_to_r53.compare_soa_recs(serial_hash, cache_serial_data)

        override = True
        force = False
        if change_list and not force:
            for zone in change_list:
                try:
                    cache_data = dyn_to_r53.read_cache(zone)
                    zone_data_aws = dyn_to_r53.retrieve_zones_aws(conn, zone)
                    zone_data_dyn = dyn_to_r53.retrieve_zones_dyn(zone)
                    zone_diff_copy_aws = copy.deepcopy(zone_data_aws)
                    if cache_data:
                        create_recs, del_recs = dyn_to_r53.diff_changes(zone_data_dyn, zone_data_aws, [zone])
                        dyn_to_r53.cleanup_records(del_recs, zone_diff_copy_aws[zone][0]['zone_id'], client)
                        dyn_to_r53.cache_to_file(zone_data_dyn, zone)
                        dyn_to_r53.cache_to_file(serial_hash, zone, True)
                    else:
                        dyn_to_r53.cache_to_file(zone_data_dyn, zone)
                        dyn_to_r53.cache_to_file(serial_hash, zone, True)
                    dyn_to_r53.copy_records(zone_data_dyn, [zone], zone_diff_copy_aws, override, client)
                except Exception as e:
                    print(e)
        elif force:
            zone_list = dyn_to_r53.get_dyn_zones()
            for zone in zone_list:
                zone_data_aws = dyn_to_r53.retrieve_zones_aws(conn, zone.name)
                zone_data_dyn = dyn_to_r53.retrieve_zones_dyn(zone.name)
                zone_diff_copy_aws = copy.deepcopy(zone_data_aws)
                create_recs, del_recs = dyn_to_r53.diff_changes(zone_data_dyn, zone_diff_copy_aws, [zone.name])
                if zone.name in zone_data_aws:
                    dyn_to_r53.copy_records(zone_data_dyn, [zone.name], zone_data_aws, override, client)
                    dyn_to_r53.cleanup_records(del_recs, zone_data_aws[zone.name][0]['zone_id'], client)
                    dyn_to_r53.cache_to_file(serial_hash, zone.name, True)
