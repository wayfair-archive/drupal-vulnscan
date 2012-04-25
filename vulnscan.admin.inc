<?php

require_once('helpers.inc');

function vulnscan_admin_settings($form, &$form_state) {
    $servers = get_all_servers_assoc();
    $sites = get_all_sites_assoc();
    $scanners = get_all_scanners_assoc();

    /* Main settings */
    $form['vulnscan_scanner_settings'] = array(
        '#type' => 'fieldset',
        '#title' => t('Scanner Settings'),
        '#collapsible' => TRUE,
        '#collapsed' => FALSE,
        '#description' => t('At least one scanner must be configured.'),
    );

    $form['vulnscan_scanner_settings']['scan_output_location'] = array(
        '#type' => 'textfield',
        '#title' => t('Scan Output Location'),
        '#default_value' => variable_get('vulnscan_scan_output_location', ''),
        '#size' => 60,
    );

    $form['vulnscan_scanner_settings']['alias'] = array(
        '#type' => 'textfield',
        '#title' => t('Web Server Virtual Path'),
        '#description' => t('Virtual Path to the scanner output location'),
        '#default_value' => variable_get('vulnscan_alias', ''),
        '#size' => 60,
    );

    $form['vulnscan_scanner_settings']['vulnscan_script_location'] = array(
        '#type' => 'textfield',
        '#title' => t('Helper script location'),
        '#description' => t('Where the scanner helper script is located'),
        '#default_value' => variable_get('vulnscan_script_location', ''),
        '#size' => 60,
    );

    $form['vulnscan_scanner_settings']['vulnscan_email_from'] = array(
        '#type' => 'textfield',
        '#title' => t('Email From'),
        '#description' => t('Email address from which emails are sent'),
        '#default_value' => variable_get('vulnscan_email_from', ''),
        '#size' => 60,
    );

    if (count($scanners)) {
        $form['vulnscan_scanner_settings']['scanners'] = array(
            '#type' => 'select',
            '#title' => t('Existing Scanners'),
            '#multiple' => TRUE,
            '#options' => $scanners,
        );
    }

    if (isset($form_state['input']['scanners'])) {
        $scanner = array_filter($form_state['input']['scanners']);
        $scanner = $scanner[0];
        $obj = get_scanner($scanner);
        
        $form['vulnscan_scanner_settings']['scanner_details'] = array(
            '#type' => 'fieldset',
            '#title' => t('Details for @scanner', array('@scanner' => $scanner)),
        );

        $form['vulnscan_scanner_settings']['scanner_details']['scanner_details_name'] = array(
            '#type' => 'textfield',
            '#title' => t('Name'),
            '#default_value' => $obj->name,
            '#size' => 60,
            '#readonly' => TRUE,
        );

        $form['vulnscan_scanner_settings']['scanner_details']['scanner_details_location'] = array(
            '#type' => 'textfield',
            '#title' => t('Location'),
            '#default_value' => $obj->location,
            '#size' => 60,
            '#readonly' => TRUE,
        );

        $form['vulnscan_scanner_settings']['scanner_details']['scanner_details_arguments'] = array(
            '#type' => 'textfield',
            '#title' => t('Arguments'),
            '#default_value' => $obj->arguments,
            '#size' => 60,
            '#readonly' => TRUE,
        );
    }

    $form['vulnscan_scanner_settings']['new_scanner'] = array(
        '#type' => 'fieldset',
        '#title' => t('New Scanner'),
    );

    $replacements = array(
        array('%{SERVER}', 'Server being scanned (used in cookies)'),
        array('%{SITE}', 'Site to scan'),
        array('%{DIR}', 'Scan result output directory'),
    );

    $header = array('Replacement', 'Meaning');

    $form['vulnscan_scanner_settings']['new_scanner']['replacements'] = array(
        '#type' => 'markup',
        '#prefix' => '<div>',
        '#markup' => theme('table', array(
            'header' => $header,
            'rows' => $replacements,
        )),
        '#suffix' => '</div>',
    );

    $form['vulnscan_scanner_settings']['new_scanner']['new_scanner_name'] = array(
        '#type' => 'textfield',
        '#title' => t('Name'),
        '#size' => 60,
    );

    $form['vulnscan_scanner_settings']['new_scanner']['new_scanner_location'] = array(
        '#type' => 'textfield',
        '#title' => t('Location'),
        '#size' => 60,
    );

    $form['vulnscan_scanner_settings']['new_scanner']['new_scanner_arguments'] = array(
        '#type' => 'textfield',
        '#title' => t('Arguments'),
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

    $form['vulnscan_sites'] = array(
        '#type' => 'fieldset',
        '#title' => t('Sites to Scan'),
        '#collapsible' => TRUE,
        '#collapsed' => FALSE,
    );

    if (count($sites) > 0) {
        $form['vulnscan_sites']['sites'] = array(
            '#type' => 'select',
            '#title' => t('Existing Sites'),
            '#description' => t('Select one or more sites to delete upon saving the form.'),
            '#multiple' => TRUE,
            '#options' => $sites,
        );
    }

    $form['vulnscan_sites']['new_site_name'] = array(
        '#type' => 'textfield',
        '#title' => t('New Site Name'),
        '#size' => 30,
    );

    $form['vulnscan_sites']['new_site_url'] = array(
        '#type' => 'textfield',
        '#title' => t('New Site URL'),
        '#size' => 30,
    );

    $form['select_scanner'] = array(
        '#type' => 'submit',
        '#submit' => array('show_scanner'),
        '#value' => t('Show Scanner Details'),
    );

    $form['submit'] = array(
        '#type' => 'submit',
        '#value' => t('Save Settings'),
    );

    return $form;
}

function vulnscan_admin_settings_submit($form, &$form_state) {
    if (isset($form_state['values']['scan_output_location']))
        variable_set('vulnscan_scan_output_location', $form_state['values']['scan_output_location']);

    if (isset($form_state['values']['vulnscan_script_location']))
        variable_set('vulnscan_script_location', $form_state['values']['vulnscan_script_location']);

    if (isset($form_state['values']['vulnscan_email_from']))
        variable_set('vulnscan_email_from', $form_state['values']['vulnscan_email_from']);

    if (isset($form_state['values']['alias']))
        variable_set('vulnscan_alias', $form_state['values']['alias']);

    if (isset($form_state['values']['scanners']))
        delete_scanners(array_filter($form_state['values']['scanners']));

    if (isset($form_state['values']['new_scanner_name']) && strlen($form_state['values']['new_scanner_name']))
        add_scanner($form_state['values']['new_scanner_name'], $form_state['values']['new_scanner_location'], $form_state['values']['new_scanner_arguments']);

    /* Delete selected servers */
    if (isset($form_state['values']['servers']))
        delete_servers(array_filter($form_state['values']['servers']));

    /* Save the new server */
    if (isset($form_state['values']['new_server']) && strlen($form_state['values']['new_server']))
        if (add_server($form_state['values']['new_server']) == false)
            form_set_error('new_server', t('An error occurred adding the server @server', array('@server' => $form_state['values']['new_server'])));

    /* Delete selected sites */
    if (isset($form_state['values']['sites']))
        delete_sites(array_filter($form_state['values']['sites']));

    if (isset($form_state['values']['new_site_name']) && strlen($form_state['values']['new_site_name']))
        add_site($form_state['values']['new_site_name'], $form_state['values']['new_site_url']);

    drupal_set_message(t('Settings saved'));
}

function show_scanner($form, &$form_state) {
    $form_state['rebuild'] = TRUE;
}

function vulnscan_admin_settings_servergroup($form, &$form_state) {
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

    drupal_set_message(t('Settings saved'));

    $form_state['rebuild'] = TRUE;
}
