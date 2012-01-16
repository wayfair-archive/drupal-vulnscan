<?php

require_once('helpers.inc');

function vulnscan_admin_settings($form, &$form_state) {
    $servers = get_all_servers_assoc();

    /* Main settings */
    $form['vulnscan_scanner_settings'] = array(
        '#type' => 'fieldset',
        '#title' => t('Scanner Settings'),
        '#collapsible' => TRUE,
        '#collapsed' => FALSE,
        '#description' => t('At least one scanner must be configured.'),
    );

    $form['vulnscan_scanner_settings']['replacements'] = array(
        '#type' => 'markup',
        '#prefix' => '<div>',
        '#markup' => t('Replacements: %{SERVER} - Server being scanned (used in cookies). %{SITE} - Site to scan (Wayfair, Admin Home, etc.). %{DIR} - Scan result output directory.'),
        '#suffix' => '</div>',
    );

    $form['vulnscan_scanner_settings']['skipfish_location'] = array(
        '#type' => 'textfield',
        '#title' => t('Skipfish Arguments'),
        '#default_value' => variable_get('vulnscan_skipfish_location', ''),
        '#size' => 60,
    );

    $form['vulnscan_scanner_settings']['scan_output_location'] = array(
        '#type' => 'textfield',
        '#title' => t('Scan Output Location'),
        '#default_value' => variable_get('vulnscan_scan_output_location', ''),
        '#size' => 60,
    );

    /* Server settings */
    $form['vulnscan_server_settings'] = array(
        '#type' => 'fieldset',
        '#title' => 'Available Servers',
        '#collapsible' => TRUE,
        '#collapsed' => FALSE,
    );

    if (count($servers) > 0) {
        $form['vulnscan_server_settings']['servers'] = array(
            '#type' => 'select',
            '#title' => t('Existing Servers'),
            '#multiple' => TRUE,
            '#description' => 'Select one or more servers to delete upon saving the form.',
            '#options' => $servers,
        );
    }

    $form['vulnscan_server_settings']['new_server'] = array(
        '#type' => 'textfield',
        '#title' => t('Add a New Server'),
        '#size' => 30
    );

    $form['submit'] = array(
        '#type' => 'submit',
        '#value' => t('Save Settings'),
    );

    return $form;
}

function vulnscan_admin_settings_submit($form, &$form_state) {
    if (isset($form_state['values']['vulnscan_skipfish_location']))
        variable_set('vulnscan_skipfish_location', $form_state['values']['skipfish_location']);

    if (isset($form_state['values']['scan_output_location']))
        variable_set('vulnscan_scan_output_location', $form_state['values']['scan_output_location']);

    /* Save the new server */
    if (isset($form_state['values']['new_server']) && strlen($form_state['values']['new_server']))
        if (add_server($form_state['values']['new_server']) == false)
            form_set_error('new_server', t('An error occurred adding the server @server', array('@server' => $form_state['values']['new_server'])));

    /* Delete selected servers */
    if (isset($form_state['values']['servers']))
        delete_servers(array_filter($form_state['values']['servers']));
}

function vulnscan_admin_settings_servergroup($form, &$form_state) {
//    form_set_error('new_servergroup', t('form_state: @state', array('@state' => var_export($form_state, TRUE))));
//    form_set_error('new_servergroup', t('form_state: @state', array('@state' => var_export($form_state, TRUE))));
    $groups = get_all_server_groups_assoc();

    $form['vulnscan_servergroup'] = array(
        '#type' => 'fieldset',
        '#title' => t('Server Group'),
    );

    if (count($groups) > 0) {
        $form['vulnscan_servergroup']['servergroup'] = array(
            '#type' => 'select',
            '#title' => t('Server Group'),
            '#options' => $groups,
        );
    }

    $form['vulnscan_servergroup']['new_servergroup'] = array(
        '#type' => 'textfield',
        '#title' => t('Add New Server Group'),
        '#size' => 30,
    );

    if (isset($form_state['input']['servergroup'])) {
        $existing_servers = get_all_servers_in_server_group_assoc($form_state['input']['servergroup']);
        $all = get_all_servers_assoc();

        /* Only show existing/add fieldsets if servers exist */
        if (count($all)) {

            $new_servers = array();
            foreach ($all as $key => $value)
                if (array_key_exists($key, $existing_servers) == false)
                    $new_servers[$key] = $value;

            if (count($existing_servers)) {
                $form['vulnscan_existing_servers'] = array(
                    '#type' => 'fieldset',
                    '#title' => t('Assigned Servers'),
                    '#collapsible' => TRUE,
                    '#collapsed' => FALSE,
                );

                $form['vulnscan_existing_servers']['existing_servers'] = array(
                    '#type' => 'select',
                    '#multiple' => TRUE,
                    '#description' => t('Select one or more to delete'),
                    '#options' => $existing_servers
                );
            }

            if (count($new_servers)) {
                $form['vulnscan_new_servers'] = array(
                    '#type' => 'fieldset',
                    '#title' => t('Add New Servers'),
                    '#collapsible' => TRUE,
                    '#collapsed' => FALSE,
                );

                $form['vulnscan_new_servers']['new_server'] = array(
                    '#type' => 'select',
                    '#multiple' => TRUE,
                    '#description' => t('Select one or more to add'),
                    '#options' => $new_servers,
                );
            }
        }
    }

    $form['select_servergroup'] = array(
        '#type' => 'submit',
        '#submit' => array('vulnscan_admin_settings_servergroup_setservergroup'),
        '#value' => t('Select Server Group'),
    );

    $form['submit'] = array(
        '#type' => 'submit',
        '#value' => t('Save Settings'),
    );

    return $form;
}

function vulnscan_admin_settings_servergroup_setservergroup($form, &$form_state) {
    $form_state['rebuild'] = TRUE;
}

function vulnscan_admin_settings_servergroup_submit($form, &$form_state) {
    if (isset($form_state['values']['new_servergroup']) && strlen($form_state['values']['new_servergroup']))
        if (add_server_group($form_state['values']['new_servergroup']) == false)
            form_set_error('new_servergroup', t('Could not add Server Group @group', array('@group' => $form['values']['new_servergroup'])));

    if (isset($form_state['values']['existing_servers'])) {
        remove_servers_in_server_group($form_state['values']['servergroup'], array_filter($form_state['values']['existing_servers']));
    }

    if (isset($form_state['values']['new_server'])) {
        if (add_servers_in_server_group($form_state['values']['servergroup'], array_filter($form_state['values']['new_server'])) == false) {
            form_set_error('new_server', t('Could not assign servers to group.'));
        }
    }

    $form_state['rebuild'] = TRUE;
}
