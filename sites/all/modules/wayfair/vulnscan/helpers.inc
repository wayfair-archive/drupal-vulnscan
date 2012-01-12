<?php

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
        db_delete('vulnscan_server')
            ->condition('name',  $value)
            ->execute();
    }
}
