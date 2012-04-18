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

function get_all_scanners() {
    return db_query('SELECT * FROM {vulnscan_scanners}');
}

function get_scanner($scanner) {
    $result = db_query('SELECT * FROM {vulnscan_scanners} WHERE name = :name', array(':name' => $scanner));
    foreach ($result as $record)
        return $record;

    return null;
}

function get_all_scanners_assoc() {
    $scanners = array();
    $result = get_all_scanners();

    foreach ($result as $record)
        $scanners[$record->name] = $record->name;

    return $scanners;
}

function add_scanner($name, $location, $arguments) {
    db_insert('vulnscan_scanners')
        ->fields(array(
            'name' => $name,
            'location' => $location,
            'arguments' => $arguments,
        ))->execute();
}

function delete_scanners($scanners = array()) {
    foreach ($scanners as $key => $value) {
        db_delete('vulnscan_scanners')
            ->condition('name', $value)
            ->execute();
    }
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
    if (user_access('scan all servers', $user))
        return TRUE;

    foreach (user_role_permissions($user->roles) as $perms) {
        foreach ($perms as $key => $value) {
            if (strpos($key, $groupname) !== FALSE)
                return TRUE;
        }
    }

    return FALSE;
}

function user_can_scan_server($user, $servername) {
    if (user_access('scan all servers', $user))
        return TRUE;

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

    foreach (get_all_scanners() as $scanner)
        $scanners[$scanner->name] = $scanner->location . ' ' . $scanner->arguments;

    return $scanners;
}

function prep_scanner($scanner_name, $scanner, $server, $site) {
    global $user;

    $output = variable_get('vulnscan_scan_output_location', '');

    $ret = str_replace('%{SERVER}', $server, $scanner);
    $ret = str_replace('%{SITE}', $site, $ret);
    
    /* Output dir should be $output/$uid/<scan> */
    if (strlen($output)) {
        $dir = $output;
        $dir .= '/' . $user->uid;
        $dir .= '/' . $server;
        $dir .= '/' . $scanner_name . ':' . strftime('%F_%T');

        $ret = str_replace('%{DIR}', $dir, $ret);
        exec("mkdir -p '$dir'");
    }
    else if (strpos($scanner, '%{DIR}')) {
        drupal_set_message(t('Scanner configuration requires %{DIR}, but the output location is not set! Please properly configure module.'), 'error');
        return false;
    }

    return $ret;
}

function run_scan_on_server($site, $server) {
    global $user;

    $scanners = scanners();
    $script = variable_get('vulnscan_script_location', '');
    $from = variable_get('vulnscan_email_from', '');
    $to = $user->mail;
    $date = strftime('%F_%T');

    if (!strlen($script)) {
        drupal_set_message(t('Helper script location must be set! Please properly configure module.'), 'error');
        return FALSE;
    }

    foreach ($scanners as $name => $location) {
        $prepped = prep_scanner($name, $location, $server, $site, $date);
        if ($prepped === FALSE)
            return FALSE;

        $prepped = str_replace("'", "\"", $prepped);
        $prepped = "{$script} -s '{$prepped}' -f '{$from}' -t '{$to}' -l http://www.google.com/";

        //drupal_set_message(t('gonna run: @cmd', array('@cmd' => $prepped)));
        exec($prepped . ' > /dev/null 2>&1 &');
    }

    return TRUE;
}

function run_scan_on_server_group($site, $group) {
    foreach (get_all_servers_in_server_group_assoc($group) as $server)
        if (run_scan_on_server($site, $server) == FALSE)
            return FALSE;

    return TRUE;
}

function run_scan_on_server_groups($site, $groups=array()) {
    foreach ($groups as $group)
        run_scan_on_server_group($site, $group);
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

function add_site($name, $url) {
    db_insert('vulnscan_sites')
        ->fields(array(
            'displayname' => $name,
            'url' => $url,
        ))->execute();
}

function delete_sites($urls=array()) {
    foreach ($urls as $url) {
        db_delete('vulnscan_sites')
            ->condition('url', $url)
            ->execute();
    }
}

/* Functions for retrieving scans */

function list_scans($user, $allusers=false) {
    $scans = array();
    $base = variable_get('vulnscan_scan_output_location', '');
    $alias = variable_get('vulnscan_alias', '');

    if (strlen($base) == 0)
        return $scans;

    if (is_dir($base . '/' . $user->uid) == false)
        return $scans;

    if (strlen($alias) == 0)
        $alias = $base;

    if ($allusers) {
        $basedir = dir($base);
        while (($uid = $basedir->read()) !== FALSE) {
            if ($uid[0] == '.')
                continue;

            if ($uid == $user->uid && user_access('view own scans') == false)
                continue;

            $u = user_load($uid);

            $serversdir = dir($base . '/' . $uid);
            while (($server = $serversdir->read()) !== FALSE) {
                if ($server[0] == '.')
                    continue;

                $serverdir = dir($base . '/' . $uid . '/' . $server);
                while (($scan = $serverdir->read()) !== FALSE) {
                    if ($scan[0] == '.')
                        continue;

                    $scans[$server][$scan . " ({$u->name})"] = $alias . '/' . $uid . '/' . $server . '/' . $scan;
                }
                $serverdir->close();
            }
            $serversdir->close();
        }
        $basedir->close();
    } else {
        if (user_access('view own scans') == false)
            return $scans;

        $basedir = dir($base . '/' . $user->uid);
        while (($server = $basedir->read()) !== FALSE) {
            if ($server[0] == '.')
                continue;

            $scans[$server] = array();

            $serverdir = dir($base . '/' . $user->uid . '/' . $server);
            while (($scan = $serverdir->read()) !== FALSE) {
                if ($scan[0] == '.')
                    continue;

                $scans[$server][$scan] = $alias . '/' . $user->uid . '/' . $server . '/' . $scan;
            }
            $serverdir->close();
        }
        $basedir->close();
    }

    return $scans;
}
