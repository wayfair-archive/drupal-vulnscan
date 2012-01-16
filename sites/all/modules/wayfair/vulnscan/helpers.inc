<?php

/* Server functions */

function get_all_servers() {
    return db_query('SELECT * FROM {vulnscan_server}');
}

function get_all_servers_assoc() {
    $servers = array();
    $result = get_all_servers();

    foreach ($result as $record)
        $servers[$record->name] = $record->name;

    return $servers;
}

function delete_servers($servers = array()) {
    /* $servers array needs to be an associative array (e.g. array('servername' => 'servername') */
    foreach ($servers as $key => $value) {
        db_delete('vulnscan_servergroupmapping')
            ->condition('servername', $value)
            ->execute();

        db_delete('vulnscan_server')
            ->condition('name',  $value)
            ->execute();
    }
}

function add_server($server) {
    if (strlen($server) == 0)
        return false;

    $name = strtoupper($server);
    $servers = get_all_servers_assoc();

    if (array_key_exists($name, $servers))
        return false;

    db_insert('vulnscan_server')
        ->fields(array(
            'name' => $name,
        ))->execute();

    return true;
}

/* Server Group functions */

function get_all_server_groups() {
    return db_query('SELECT * FROM {vulnscan_servergroup}');
}

function get_all_server_groups_assoc() {
    $groups = array();
    $result = get_all_server_groups();

    foreach ($result as $record)
        $groups[$record->groupname] = $record->groupname;

    return $groups;
}

function add_server_group($groupname) {
    if (strlen($groupname) == 0)
        return false;

    $groups = get_all_server_groups_assoc();
    if (array_key_exists($groupname, $groups))
        return false;

    db_insert('vulnscan_servergroup')
        ->fields(array(
            'groupname' => $groupname,
        ))->execute();

    return true;
}

function get_all_servers_in_server_group($groupname) {
    return db_query('SELECT servername FROM {vulnscan_servergroupmapping} WHERE groupname = :groupname', array(':groupname' => $groupname));
}

function get_all_servers_in_server_group_assoc($groupname) {
    $servers = array();
    $result = get_all_servers_in_server_group($groupname);

    foreach ($result as $record)
        $servers[$record->servername] = $record->servername;

    return $servers;
}

function get_all_servers_in_server_group_for_default($groupname) {
    $servers = array();
    $result = get_all_servers_in_server_group($groupname);

    foreach ($result as $record)
        $servers[$record->servername] = $record->servername;

    return $servers;
}

function remove_servers_in_server_group($groupname, $servers=array()) {
    foreach ($servers as $key => $value) {
        db_delete('vulnscan_servergroupmapping')
            ->condition('groupname', $groupname)
            ->condition('servername', $value)
            ->execute();
    }
}

function add_servers_in_server_group($groupname, $servers=array()) {
    foreach ($servers as $server)
        db_insert('vulnscan_servergroupmapping')
            ->fields(array(
                'groupname' => $groupname,
                'servername' => $server,
            ))->execute();

    return true;
}

/* User accesses */
function user_can_scan_group($user, $groupname) {
    foreach (user_role_permissions($user->roles) as $perms) {
        foreach ($perms as $key => $value) {
            if (strpos($key, $groupname) !== FALSE)
                return TRUE;
        }
    }

    return FALSE;
}

function user_can_scan_server($user, $servername) {
    $groups = get_all_server_groups();

    foreach ($groups as $group) {
        $servers = get_all_servers_in_server_group($group->groupname);

        foreach ($servers as $server)
            if (!strcmp($server->servername, $servername))
                if (user_can_scan_group($user, $group->groupname))
                    return TRUE;
    }

    return FALSE;
}

function user_scannable_groups($user) {
    $ret = array();
    $groups = get_all_server_groups_assoc();

    foreach ($groups as $key => $value)
        if (user_can_scan_group($user, $key))
            $ret[$key] = $value;

    return $ret;
}

/* Scanning functions */

function get_site_url($site) {
    switch ($site) {
        case t('Admin Home'):
            return 'http://adminwayfaircom.csnzoo.com/';
        case t('Wayfair'):
            return 'http://wayfaircom.csnzoo.com/';
    }
}

function scanners() {
    $scanners = array();

    $skipfish = variable_get('vulnscan_skipfish_location', '');
    if (strlen($skipfish))
        $scanners[] = $skipfish;

    return $scanners;
}

function prep_scanner($scanner, $server, $site) {
    global $user;

    $output = variable_get('vulnscan_scan_output_location', '');

    $ret = str_replace('%{SERVER}', $server, $scanner);
    $ret = str_replace('%{SITE}', $site, $ret);
    
    /* Output dir should be $output/$uid/<scan> */
    if (strlen($output)) {
        $ret = str_replace('%{DIR}', $output . '/' . $user->uid, $ret);
    }
    else if (strpos($scanner, '%{DIR}')) {
        drupal_set_message(t('Scanner configuration requires %{DIR}, but the output location is not set! Please properly configure module.'), 'error');
        return false;
    }

    return $ret;
}

function run_scan_on_server_groups($site, $groups=array()) {
    $scanners = scanners();

    foreach ($groups as $group) {
        foreach (get_all_servers_in_server_group_assoc($group) as $server) {
            foreach ($scanners as $scanner) {
                $prepped = prep_scanner($scanner, $server, $site);
                if ($prepped === False)
                    return false;

                exec(t($prepped . ' > /dev/null 2>&1 &'));
            }
        }
    }

    return true;
}

/* Functions for sites to scan */

function get_all_sites() {
    return db_query('SELECT * FROM {vulnscan_sites}');
}

function get_all_sites_assoc() {
    $result = get_all_sites();
    $sites = array();

    foreach ($result as $record)
        $sites[$record->url] = $record->displayname;

    return $sites;
}
